/*
 * pgseccomp.c
 *
 * Provides seccomp syscall filtering at the PostgreSQL parent process
 * level (inherited by all subsequent child processes) and separately at the
 * client backend level.
 *
 * Joe Conway <joe.conway@crunchydata.com>
 *
 * This code is released under the PostgreSQL license.
 *
 * Copyright 2015-2017 Crunchy Data Solutions, Inc.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without a written
 * agreement is hereby granted, provided that the above copyright notice
 * and this paragraph and the following two paragraphs appear in all copies.
 *
 * IN NO EVENT SHALL CRUNCHY DATA SOLUTIONS, INC. BE LIABLE TO ANY PARTY
 * FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES,
 * INCLUDING LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
 * DOCUMENTATION, EVEN IF THE CRUNCHY DATA SOLUTIONS, INC. HAS BEEN ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE CRUNCHY DATA SOLUTIONS, INC. SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE. THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE CRUNCHY DATA SOLUTIONS, INC. HAS NO
 * OBLIGATIONS TO PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 */
#include "postgres.h"

#include <seccomp.h>
#include <sys/prctl.h>

#include "catalog/pg_type.h"
#include "libpq/auth.h"
#include "miscadmin.h"
#include "nodes/bitmapset.h"
#include "nodes/execnodes.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"
#include "utils/tuplestore.h"
#include "utils/varlena.h"

PG_MODULE_MAGIC;

typedef struct seccomp_filter
{
	char		   *source;
	int				def;
	Bitmapset	   *allow;
	Bitmapset	   *log;
	Bitmapset	   *error;
	Bitmapset	   *kill;
} seccomp_filter;

#define NUM_SECCOMP_FILTER_ATTS		4
#define NUM_SECCOMP_RULES			400
typedef struct seccomp_rule
{
	int			syscallnum;		/* syscall number */
	char	   *syscall;		/* syscall name string */
	int			rule_action;	/* action level for this rule */
	char	   *source;			/* filter source for this rule */
} seccomp_rule;

typedef struct seccompHashEntry
{
        int					syscallnum;
        seccomp_rule	   *scr_entry;
} seccompHashEntry;

/* seccomp enforce actions in increasing order of precedence */
#define PG_SECCOMP_ALLOW    0  /* allow */
#define PG_SECCOMP_LOG      1  /* log */
#define PG_SECCOMP_ERROR    2  /* permission denied error */
#define PG_SECCOMP_KILL     3  /* kill process */
const struct config_enum_entry seccomp_options[] = {
	{"allow", PG_SECCOMP_ALLOW, false},
	{"log", PG_SECCOMP_LOG, false},
	{"error", PG_SECCOMP_ERROR, false},
	{"kill", PG_SECCOMP_KILL, false},
	{NULL, 0}
};

static ClientAuthentication_hook_type next_client_auth_hook = NULL;
static seccomp_filter *global_filter = NULL;
static seccomp_filter *session_filter = NULL;
static seccomp_filter *client_filter = NULL;

static int hdef = -1;
static char *hsource = NULL;

static bool seccomp_enabled = false;
/* postmaster level */
static int global_syscall_default = PG_SECCOMP_ALLOW;
static char *global_syscall_allow_string = NULL;
static char *global_syscall_log_string = NULL;
static char *global_syscall_error_string = NULL;
static char *global_syscall_kill_string = NULL;
/* session level */
static int session_syscall_default = PG_SECCOMP_ALLOW;
static char *session_syscall_allow_string = NULL;
static char *session_syscall_log_string = NULL;
static char *session_syscall_error_string = NULL;
static char *session_syscall_kill_string = NULL;
static char *session_roles_string = NULL;
/* client level */
static int client_syscall_default = PG_SECCOMP_ALLOW;
static char *client_syscall_allow_string = NULL;
static char *client_syscall_log_string = NULL;
static char *client_syscall_error_string = NULL;
static char *client_syscall_kill_string = NULL;
static bool client_filter_loaded = false;

/* static functions */
static bool check_syscall_list(char **newval);
static bool get_role_in_list(char *slist, char *rolename);
static int get_role_default(int sdef, char *rolename);
static char *get_role_list(char *slist, char *saction, char *rolename);
static void CA_hook(Port *port, int status);
static void ovly_hash_from_bitmap(seccomp_filter *f, HTAB *seccompHash);
static void put_hash(HTAB *seccompHash, const char *context,
					 Tuplestorestate *tupstore, TupleDesc tupdesc);
static int get_seccomp_opt_num(const char *val);
static const char *get_seccomp_opt_str(int val);
static bool load_seccomp_filter(char *context);
static bool apply_seccomp_list(scmp_filter_ctx	*ctx, const char *slist,
							   uint32_t rule_action, uint32_t def_action,
							   seccomp_filter *current_filter);
static char*expand_seccomp_list(char *slist, char *glist, char *saction);
static void set_filter_def_action(int default_action,
								  seccomp_filter *current_filter,
								  char *context);

/* exported functions */
void _PG_init(void);
void _PG_fini(void);
bool check_session_roles_list(char **newval, void **extra, GucSource source);
bool check_global_syscall_list(char **newval, void **extra, GucSource source);
bool check_session_syscall_list(char **newval, void **extra, GucSource source);
Datum pg_get_seccomp_filter(PG_FUNCTION_ARGS);

/*
 * check_syscall_list: GUC check_hook
 * check various lists of syscalls used for seccomp enforcement
 */
static bool
check_syscall_list(char **newval)
{
	char		   *rawstring = NULL;
	List		   *elemlist = NIL;
	ListCell	   *l;
	bool			result = true;

	/* Need a modifiable copy of string */
	rawstring = pstrdup(*newval);

	/* Parse string into list of syscalls */
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
	{
		GUC_check_errdetail("List syntax is invalid.");
		result = false;
		goto out;
	}

	foreach(l, elemlist)
	{
		char   *cursyscall = (char *) lfirst(l);
		int		syscallnum;

		/* resolve the syscall name to its number on the current arch */
		syscallnum = seccomp_syscall_resolve_name(cursyscall);
		if (syscallnum < 0)
		{
			/* invalid syscall name */
			GUC_check_errcode(ERRCODE_INVALID_PARAMETER_VALUE);
			GUC_check_errdetail("Seccomp failed to resolve syscall: \"%s\"",
								cursyscall);
			result = false;
			goto out;
		}
	}

out:
	/* safe to release if NIL */
	list_free(elemlist);

	/* but pfree is not */
	if (rawstring)
		pfree(rawstring);

	return result;
}

/*
 * check_session_roles_list: GUC check_hook
 * check list of roles used for custom seccomp enforcement
 * Note: this just checks list syntax, not rolename validity
 */
bool
check_session_roles_list(char **newval, void **extra, GucSource source)
{
	char		   *rawstring = NULL;
	List		   *elemlist = NIL;
	bool			result = true;

	/* Need a modifiable copy of string */
	rawstring = pstrdup(*newval);

	/* Parse string into list of syscalls */
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
	{
		GUC_check_errdetail("List syntax is invalid.");
		result = false;
		goto out;
	}

out:
	/* safe to release if NIL */
	list_free(elemlist);

	/* but pfree is not */
	if (rawstring)
		pfree(rawstring);

	return result;
}

bool
check_global_syscall_list(char **newval, void **extra, GucSource source)
{
	return check_syscall_list(newval);
}

bool
check_session_syscall_list(char **newval, void **extra, GucSource source)
{
	/*
	 * If the only character of the passed *newval string is '*'
	 * then use the global allow list. Only applies to children
	 * of the postmaster.
	 */
	if (strlen(*newval) == 1 && *newval[0] == '*')
		return true;
	else
		return check_syscall_list(newval);
}

void
_PG_init(void)
{
    /* Be sure we do initialization only once */
    static bool inited = false;

    if (inited)
        return;

    /* Must be loaded with shared_preload_libraries */
    if (!process_shared_preload_libraries_in_progress)
        ereport(ERROR, (errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
                errmsg("pgseccomp must be loaded via shared_preload_libraries")));

	/* overall enable/disable switch */
	DefineCustomBoolVariable("pgseccomp.enabled",
							 "Turns on seccomp syscall enforcement",
							 NULL, &seccomp_enabled, false, PGC_POSTMASTER,
							 0, NULL, NULL, NULL);

	/* global lists installed at the postmaster level on startup */
	DefineCustomStringVariable("pgseccomp.global_syscall_allow",
							   "Seccomp global syscall allow list",
							   NULL, &global_syscall_allow_string,
							   "", PGC_POSTMASTER,
							   0, check_global_syscall_list, NULL, NULL);

	DefineCustomStringVariable("pgseccomp.global_syscall_log",
							   "Seccomp global syscall log list",
							   NULL, &global_syscall_log_string,
							   "", PGC_POSTMASTER,
							   0, check_global_syscall_list, NULL, NULL);

	DefineCustomStringVariable("pgseccomp.global_syscall_error",
							   "Seccomp global syscall error list",
							   NULL, &global_syscall_error_string,
							   "", PGC_POSTMASTER,
							   0, check_global_syscall_list, NULL, NULL);

	DefineCustomStringVariable("pgseccomp.global_syscall_kill",
							   "Seccomp global syscall kill list",
							   NULL, &global_syscall_kill_string,
							   "", PGC_POSTMASTER,
							   0, check_global_syscall_list, NULL, NULL);

	DefineCustomEnumVariable("pgseccomp.global_syscall_default",
							 "Seccomp global syscall default action",
							 NULL, &global_syscall_default,
							 PG_SECCOMP_ALLOW, seccomp_options, PGC_POSTMASTER,
							 0, NULL, NULL, NULL);

	/* session lists installed after authentication */
	DefineCustomStringVariable("pgseccomp.session_syscall_allow",
							   "Seccomp backend session syscall allow list",
							   NULL, &session_syscall_allow_string,
							   "*", PGC_SIGHUP,
							   0, check_session_syscall_list, NULL, NULL);

	DefineCustomStringVariable("pgseccomp.session_syscall_log",
							   "Seccomp backend session syscall log list",
							   NULL, &session_syscall_log_string,
							   "*", PGC_SIGHUP,
							   0, check_session_syscall_list, NULL, NULL);

	DefineCustomStringVariable("pgseccomp.session_syscall_error",
							   "Seccomp backend session syscall error list",
							   NULL, &session_syscall_error_string,
							   "*", PGC_SIGHUP,
							   0, check_session_syscall_list, NULL, NULL);

	DefineCustomStringVariable("pgseccomp.session_syscall_kill",
							   "Seccomp backend session syscall kill list",
							   NULL, &session_syscall_kill_string,
							   "*", PGC_SIGHUP,
							   0, check_session_syscall_list, NULL, NULL);

	DefineCustomEnumVariable("pgseccomp.session_syscall_default",
							 "Seccomp backend session syscall default action",
							 NULL, &session_syscall_default,
							 PG_SECCOMP_ALLOW, seccomp_options, PGC_SIGHUP,
							 0, NULL, NULL, NULL);

	DefineCustomStringVariable("pgseccomp.session_roles",
							   "List of roles with customized syscall lists",
							   NULL, &session_roles_string,
							   "", PGC_SIGHUP,
							   0, check_session_roles_list, NULL, NULL);

	/*
	 * If seccomp filtering is requested, load the global filter.
	 * The list of allowed syscalls may be ratched down further
	 * in specific backends based on the actual needs by backend type.
	 */
	if(!load_seccomp_filter("postmaster"))
	{
		ereport(FATAL,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("failed to load global seccomp filter")));
	}


	/* Install backend session post-auth hook */
	next_client_auth_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = CA_hook;

    inited = true;
}

void
_PG_fini(void)
{
	ClientAuthentication_hook = next_client_auth_hook;
}

static bool
get_role_in_list(char *slist, char *rolename)
{
	char		   *rawstring = NULL;
	List		   *elemlist = NIL;
	ListCell	   *l;
	bool			result = false;

	/* Need a modifiable copy */
	rawstring = pstrdup(slist);

	/* Parse string into list of syscalls */
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
		goto out;

	/* add syscall specific rules to the filter */
	foreach(l, elemlist)
	{
		char   *listrole = (char *) lfirst(l);

		if (strcmp(listrole, rolename) == 0)
		{
			result = true;
			goto out;
		}
	}

out:
	/* safe to release if still NIL */
	list_free(elemlist);

	/* but pfree is not */
	if (rawstring)
		pfree(rawstring);

	return result;
}

static int
get_role_default(int sdef, char *rolename)
{
	char		 *cfgvarname;
	const char   *ret;

	cfgvarname = psprintf("session_syscall_default.%s", rolename);
	ret = GetConfigOption(cfgvarname, true, false);
	if (ret != NULL)
	{
		int rc = get_seccomp_opt_num(ret);

		if (rc >= PG_SECCOMP_ALLOW && rc <= PG_SECCOMP_KILL)
			return rc;
		else
			return sdef;
	}
	else
		return sdef;
}

static char*
get_role_list(char *slist, char *saction, char *rolename)
{
	char		   *cfgvarname;
	char		   *ret;
	MemoryContext	oldcontext;

	cfgvarname = psprintf("session_syscall_%s.%s", saction, rolename);

	oldcontext = MemoryContextSwitchTo(TopMemoryContext);
	ret = GetConfigOptionByName(cfgvarname, NULL, true);
	MemoryContextSwitchTo(oldcontext);

	if (ret != NULL)
		return ret;
	else
		return slist;
}

/*
 * CA_hook
 *
 * Entrypoint of the client authentication hook.
 * It applies session level seccomp filters according to GUC settings.
 */
static void
CA_hook(Port *port, int status)
{
	/*
	 * If authentication failed, the supplied socket will be
	 * closed soon, so we don't need to do anything here.
	 */
	if (status != STATUS_OK)
	{
		if (next_client_auth_hook)
			(*next_client_auth_hook)(port, status);

		return;
	}

	/*
	 * If username is in the session roles list, look for customized
	 * syscall default and lists for that role
	 */
	if (get_role_in_list(session_roles_string, port->user_name))
	{
		session_syscall_default = get_role_default(session_syscall_default,
												   port->user_name);
		session_syscall_allow_string = get_role_list(session_syscall_allow_string,
													 "allow", port->user_name);
		session_syscall_log_string = get_role_list(session_syscall_log_string,
												   "log", port->user_name);
		session_syscall_error_string = get_role_list(session_syscall_error_string,
													 "error", port->user_name);
		session_syscall_kill_string = get_role_list(session_syscall_kill_string,
													"kill", port->user_name);
	}

	/* If seccomp filtering is requested, do the backend lockdown */
	if (IsUnderPostmaster)
	{
		if(!load_seccomp_filter("session"))
		{
			ereport(FATAL,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("failed to load session seccomp filter")));
		}
	}

	if (next_client_auth_hook)
		(*next_client_auth_hook)(port, status);
}

static void
ovly_hash_from_bitmap(seccomp_filter *f, HTAB *seccompHash)
{
	int					syscallnum;
	seccompHashEntry   *hentry;
	HASH_SEQ_STATUS		status;
	Bitmapset		   *fbms;
	Bitmapset		   *fltrbms;

	/*
	 * Build a merged bitmap set from the seccomp filter being overlaid.
	 * We ensured no overlap of syscalls within all bitmaps in
	 * load_seccomp_filter(), so it should be safe to just merge all the
	 * syscall numbers found in the 4 bitmap sets.
	 * 
	 * Since it is only being used in order to know what the syscall numbers
	 * of interest are, we really don't care/need to have a separate set
	 * per action.
	 */
	fbms = bms_union(bms_union(bms_union(f->kill, f->error), f->log), f->allow);

	/*
	 * Combine the values from the current hash table with the merged overlay
	 * bitmap set. 
	 */
	fltrbms = bms_copy(fbms);
	hash_seq_init(&status, seccompHash);
	while ((hentry = (seccompHashEntry *) hash_seq_search(&status)) != NULL)
		fltrbms = bms_add_member(fltrbms, hentry->scr_entry->syscallnum);

	/*
	 * Now iterate through the combined bitmap set and fix up the hash table
	 */
	syscallnum = -1;
	while ((syscallnum = bms_next_member(fltrbms, syscallnum)) >= 0)
	{
		bool			found;
		seccomp_rule   *scr;
		int				faction = -1;

		hentry = (seccompHashEntry *) hash_search(seccompHash,
												  (const void *) &syscallnum,
												  HASH_ENTER, &found);

		if (bms_is_member(syscallnum, fbms))
		{
			/*
			 * This syscall is a new one from the overlay bitmap set
			 * so we must figure out for which action the syscall rule
			 * originated.
			 */
			if (bms_is_member(syscallnum, f->allow))
				faction = PG_SECCOMP_ALLOW;
			else if (bms_is_member(syscallnum, f->log))
				faction = PG_SECCOMP_LOG;
			else if (bms_is_member(syscallnum, f->error))
				faction = PG_SECCOMP_ERROR;
			else if (bms_is_member(syscallnum, f->kill))
				faction = PG_SECCOMP_KILL;
		}

		if (!found)
		{
			char	   *cursyscall;

			/*
			 * If an entry does not exist in the hash table, we must add it.
			 * However, the default action from the hash table still wins if
			 * it takes precedence over that of the overlay rule.
			 */
			scr = palloc(sizeof(seccomp_rule));
			scr->syscallnum = syscallnum;

			/*
			 * Resolver returns NULL on error. Given how we got here that
			 * should never happen. We must free() the result to avoid leakage.
			 */
			cursyscall =  seccomp_syscall_resolve_num_arch(seccomp_arch_native(),
														   syscallnum);
			if (cursyscall)
			{
				scr->syscall = pstrdup(cursyscall);
				free(cursyscall);
			}
			else
				scr->syscall = pstrdup("unknown");

			/*
			 * Figure out if the rule action from the overlay beats the
			 * default action for the hash table.
			 */
			if (faction >= hdef)
			{
				scr->rule_action = faction;
				scr->source = f->source;
			}
			else
			{
				scr->rule_action = hdef;
				scr->source = hsource;
			}

			hentry->syscallnum = syscallnum;
			hentry->scr_entry = scr;
		}
		else
		{
			scr = hentry->scr_entry;

			/*
			 * If an entry does exist, we must first determine if this syscall
			 * exists in the overlay filter or only in the hash table. If the
			 * former, determine whether the new rule precedence overrides the
			 * old one. If the latter, check against the overlay default instead. 
			 */
			if (bms_is_member(syscallnum, fbms))
			{
				/* entry is in both sets, see which wins */
				if (faction >= scr->rule_action)
				{
					/* new rule takes precedence */
					scr->rule_action = faction;
					scr->source = f->source;
				}
			}
			else
			{
				/* entry is in hash table only, check against incoming default */
				if (f->def >= scr->rule_action)
				{
					/* new rule takes precedence */
					scr->rule_action = f->def;
					scr->source = f->source;
				}
			}
		}
	}

	/* Set up hash table defaults in case there is a next round */
	if (f->def >= hdef)
	{
		hdef = f->def;
		hsource = f->source;
	}
}

static void
put_hash(HTAB *seccompHash, const char *context,
		 Tuplestorestate *tupstore, TupleDesc tupdesc)
{
	Datum				values[NUM_SECCOMP_FILTER_ATTS];
	bool				nulls[NUM_SECCOMP_FILTER_ATTS];
	seccompHashEntry   *hentry;
	seccomp_rule	   *scr;
	HASH_SEQ_STATUS		status;
	char			   *buf;

	/* create entry for the default rule */
	memset(values, 0, sizeof(values));
	memset(nulls, 0, sizeof(nulls));

	values[0] = PointerGetDatum(cstring_to_text("<default>"));
	values[1] = Int32GetDatum(-1);

	buf = psprintf("%s->%s", hsource, get_seccomp_opt_str(hdef));
	values[2] = PointerGetDatum(cstring_to_text(buf));

	values[3] = PointerGetDatum(cstring_to_text(context));

	/* shove row into tuplestore */
	tuplestore_putvalues(tupstore, tupdesc, values, nulls);

	/* Process the hash table and fill the tuplestore */
	hash_seq_init(&status, seccompHash);
	while ((hentry = (seccompHashEntry *) hash_seq_search(&status)) != NULL)
	{
		char	   *buf;

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		scr = hentry->scr_entry;
		buf = psprintf("%s->%s", scr->source,
								 get_seccomp_opt_str(scr->rule_action));

		values[0] = PointerGetDatum(cstring_to_text(scr->syscall));
		values[1] = Int32GetDatum(scr->syscallnum);
		values[2] = PointerGetDatum(cstring_to_text(buf));
		values[3] = PointerGetDatum(cstring_to_text(context));

		/* shove row into tuplestore */
		tuplestore_putvalues(tupstore, tupdesc, values, nulls);
	}
}

static int
get_seccomp_opt_num(const char *val)
{
	const struct config_enum_entry *entry;

	/* convert string to enforcement action levels */
	for (entry = seccomp_options; entry->name; entry++)
		if (strcmp(entry->name, val) == 0)
			return entry->val;

	return -1;
}

static const char *
get_seccomp_opt_str(int val)
{
	const struct config_enum_entry *entry;

	/* stringify the enforcement action levels */
	for (entry = seccomp_options; entry->name; entry++)
		if (entry->val == val)
			return entry->name;

	return "unknown";
}

PG_FUNCTION_INFO_V1(pg_get_seccomp_filter);
Datum
pg_get_seccomp_filter(PG_FUNCTION_ARGS)
{
	seccomp_filter	   *g = global_filter;
	seccomp_filter	   *s = session_filter;
	seccomp_filter	   *c = client_filter;
	HASHCTL         	ctl;
	HTAB			   *seccompHash = NULL;
	ReturnSetInfo	   *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc			tupdesc;
	Tuplestorestate	   *tupstore;
	MemoryContext		per_query_ctx;
	MemoryContext		oldcontext;

	/* Bail out if seccomp is not enabled */
	if (!seccomp_enabled)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("seccomp is not enabled")));

	/* Check to see if caller supports us returning a tuplestore */
	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));
	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not " \
						"allowed in this context")));

	/* Switch into long-lived context to construct returned data structures */
	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	/* Build a tuple descriptor for our result type */
	/* need a tuple descriptor representing three TEXT columns */
	tupdesc = CreateTemplateTupleDesc(NUM_SECCOMP_FILTER_ATTS);
	TupleDescInitEntry(tupdesc, (AttrNumber) 1, "syscall",
					   TEXTOID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2, "syscallnum",
					   INT4OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 3, "filter_action",
					   TEXTOID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 4, "context",
					   TEXTOID, -1, 0);

	/* Build a tuplestore to return our results in */
	tupstore = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	/*
	 * We need to iterate through 4 bitmap sets each, across two or three
	 * filters (global, session, client), applying the below logic, in
	 * order to determine which action applies to what syscall. The most
	 * straighforward way to do that seems to be to build a hash table since
	 * the filter sets may overlap, and the syscall numbers may vary with
	 * architecture.
	 *
	 * The aforementioned logic is:
	 * 1. The "global" filter is evaluated first. Then "session", then "client"
	 *    if applicable.
	 * 2. For a given filter, each syscall action is either the action
	 *    value given in a syscall-specific rule, or the default action. 
	 * 3. For any given syscall, the "last-seen action value of highest
	 *    precedence" is applied. The precedence in order of high-to-low
	 *    is: kill, error, log, allow.
	 *
	 * At the global level, only the global filter matters, so the
	 * logic is easy -- just reguritate the filter as tuples.
	 *
	 * At the session level, there are four combinations of filter sets
	 * to consider, and potentially two iterations
	 * (once for global + session, once for that result + client):
	 * s1 (global, or global + session)
	 * s2 (session, or client)
	 *
	 * C1. Intersection of s1 + s2
	 * C2. In s1, not in s2
	 * C3. In s2, not in s1
	 * C4. Not in s1 or s2
	 *
	 * C1, C2, C3 are handled by ovly_hash_from_bitmap()
	 * C4 is covered by the final "<default>" entry in the hash table.
	 */

	/* initialize hash table static vars */
	hdef = -1;
	hsource = NULL;

	/* set up actual hash table */
	memset(&ctl, 0, sizeof(ctl));
	ctl.keysize = sizeof(int);
	ctl.entrysize = sizeof(seccompHashEntry);
	seccompHash = hash_create("syscall rules", NUM_SECCOMP_RULES,
							  &ctl, HASH_ELEM | HASH_BLOBS);

	/* First overlay the global filter */
	ovly_hash_from_bitmap(g, seccompHash);

	/* and flush to the tuplestore */
	put_hash(seccompHash, "global", tupstore, tupdesc);

	/* Next overlay the session filter */
	ovly_hash_from_bitmap(s, seccompHash);

	/* If the client filter has been loaded, overlay it also */
	if (client_filter_loaded)
		ovly_hash_from_bitmap(c, seccompHash);

	/* and flush to the tuplestore */
	put_hash(seccompHash, "session", tupstore, tupdesc);

	/* wrap it up */
	tuplestore_donestoring(tupstore);

	/* Reset context */
	MemoryContextSwitchTo(oldcontext);

	return (Datum) 0;
}

/*
 * Create and load seccomp filter for the requested context.
 *
 * Return false on error and let the caller decide what to do
 * rather than throwing an ERROR (or FATAL) here.
 */
static bool
load_seccomp_filter(char *context)
{
	char		   *allow_list = NULL;
	char		   *log_list = NULL;
	char		   *error_list = NULL;
	char		   *kill_list = NULL;
	int				default_action;
	uint32_t		def_action;
	scmp_filter_ctx	ctx = NULL;
	int				rc;
	bool			result = true;
	MemoryContext	oldcontext;
	seccomp_filter *current_filter = NULL;

	/* should not happen */
	if (context == NULL ||
		!((strcmp(context, "postmaster") == 0) ||
		  (strcmp(context, "session") == 0) ||
		  (strcmp(context, "client") == 0)))
	{
		ereport(WARNING, (errmsg("invalid seccomp context")));
		return false;
	}

	/* if seccomp is disabled just return with success */
	if (!seccomp_enabled)
	{
		ereport(LOG, (errmsg("seccomp disabled")));
		return true;
	}

	/*
	 * If the only character of the passed syscall_list is '*'
	 * then use the global allow list. Only applies to sessions
	 * which are children of the postmaster.
	 */
	if (strcmp(context, "session") == 0)
	{
		/* in a backend session */
		/* we are going to need this later */
		oldcontext = MemoryContextSwitchTo(TopMemoryContext);
		session_filter = palloc0(sizeof(seccomp_filter));
		session_filter->source = pstrdup("session");
		MemoryContextSwitchTo(oldcontext);
		current_filter = session_filter;

		allow_list = expand_seccomp_list(session_syscall_allow_string,
										 global_syscall_allow_string,
										 "allow");
		log_list = expand_seccomp_list(session_syscall_log_string,
										 global_syscall_log_string,
										 "log");
		error_list = expand_seccomp_list(session_syscall_error_string,
										 global_syscall_error_string,
										 "error");
		kill_list = expand_seccomp_list(session_syscall_kill_string,
										 global_syscall_kill_string,
										 "kill");

		default_action = session_syscall_default;
		/*
		 * Fastpath: if the lists were all defaulted to their
		 * respective global list, and the session value of
		 * default_action is also the same as the global setting,
		 * just exit with success immediately. This avoids creating
		 * another identical seccomp bpf filter which will just
		 * slow everything down for no particular reason.
		 */
		if (default_action == global_syscall_default &&
				allow_list == global_syscall_allow_string &&
				log_list == global_syscall_log_string &&
				error_list == global_syscall_error_string &&
				kill_list == global_syscall_kill_string)
			return true;
	}
	else if (strcmp(context, "client") == 0)
	{
		/* interactive client filter */
		/* we are going to need this later */
		oldcontext = MemoryContextSwitchTo(TopMemoryContext);
		client_filter = palloc0(sizeof(seccomp_filter));
		client_filter->source = pstrdup("client");
		MemoryContextSwitchTo(oldcontext);
		current_filter = client_filter;

		/* any required expansion is already done */
		allow_list = client_syscall_allow_string;
		log_list = client_syscall_log_string;
		error_list = client_syscall_error_string;
		kill_list = client_syscall_kill_string;
		default_action = client_syscall_default;
	}
	else
	{
		/* in the postmaster */
		/* we are going to need this later */
		oldcontext = MemoryContextSwitchTo(TopMemoryContext);
		global_filter = palloc0(sizeof(seccomp_filter));
		global_filter->source = pstrdup("global");
		MemoryContextSwitchTo(oldcontext);
		current_filter = global_filter;

		allow_list = global_syscall_allow_string;
		log_list = global_syscall_log_string;
		error_list = global_syscall_error_string;
		kill_list = global_syscall_kill_string;
		default_action = global_syscall_default;
	}

	/* Disable ptrace bybass */
	rc = prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
	if (rc < 0)
	{
		ereport(WARNING,
				(ERRCODE_SYSTEM_ERROR,
				 errmsg("seccomp could not set dumpable: %m")));
		result = false;
		goto out;
	}

	/* set the seccomp default action */
	if (default_action == PG_SECCOMP_ERROR)
		def_action = SCMP_ACT_ERRNO(EACCES);
	else if (default_action == PG_SECCOMP_KILL)
		def_action = SCMP_ACT_KILL;
	else if (default_action == PG_SECCOMP_LOG)
		def_action = SCMP_ACT_LOG;
	else if (default_action == PG_SECCOMP_ALLOW)
		def_action = SCMP_ACT_ALLOW;
	else
	{
		/* unknown enforce action type */
		ereport(WARNING,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("seccomp default action action unknown")));
		result = false;
		goto out;
	}
	/* preserve and log the setting */
	set_filter_def_action(default_action, current_filter, context);

	/* Initialize seccomp with default action */
	ctx = seccomp_init(def_action);
	if (ctx == NULL)
	{
		ereport(WARNING, (errcode(ERRCODE_OUT_OF_MEMORY),
						  errmsg("out of memory")));
		result = false;
		goto out;
	}

	/*
	 * By default, libseccomp will set up audit logging
	 * such that actions KILL and LOG will get audit records,
	 * however ERRNO will not. Arrange to have all not-allowed
	 * syscalls logged instead.
	 */
	rc = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_LOG, 1);
	if (rc != 0)
	{
		ereport(WARNING,
				(errcode(ERRCODE_SYSTEM_ERROR),
				 errmsg("seccomp failed to set audit actions")));
		result = false;
		goto out;
	}

	if (!
		 (apply_seccomp_list(&ctx, allow_list, SCMP_ACT_ALLOW,
							 def_action, current_filter) &&
		  apply_seccomp_list(&ctx, log_list, SCMP_ACT_LOG,
							 def_action, current_filter) &&
		  apply_seccomp_list(&ctx, error_list, SCMP_ACT_ERRNO(EACCES),
							 def_action, current_filter) &&
		  apply_seccomp_list(&ctx, kill_list, SCMP_ACT_KILL,
							 def_action, current_filter)))
	{
		result = false;
		goto out;
	}

	/*
	 * Although libseccomp will silently throw away repeated filter
	 * rules against the same syscall (unless arguments are checked,
	 * which we are not supporting here), it can lead to confusing
	 * results, so disallow that here.
	 */
	if (bms_overlap(current_filter->allow, current_filter->log) ||
		bms_overlap(current_filter->error, current_filter->kill) ||
		bms_overlap(bms_union(current_filter->allow, current_filter->log),
					bms_union(current_filter->error, current_filter->kill)))
	{
		ereport(WARNING,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("seccomp failed due to overlapping rule sets")));
		result = false;
		goto out;
	}

	/* Finally, actually load the filter */
	rc = seccomp_load(ctx);
	if (rc != 0)
	{
		ereport(WARNING,
				(errcode(ERRCODE_SYSTEM_ERROR),
				 errmsg("seccomp failed to load rule set")));
		result = false;
		goto out;
	}

out:
	/* safe to release if NULL/NIL */
	seccomp_release(ctx);

	return result;
}

static bool
apply_seccomp_list(scmp_filter_ctx	*ctx, const char *slist,
				   uint32_t rule_action, uint32_t def_action,
				   seccomp_filter *current_filter)
{
	char		   *rawstring = NULL;
	List		   *elemlist = NIL;
	ListCell	   *l;
	bool			result = true;
	MemoryContext	oldcontext;

	/* 
	 * libseccomp disallows the case where individual syscall rules
	 * are created with the same as the default action. Therefore,
	 * be careful not to add those rules to the filter we are creating.
	 */
	if (rule_action == def_action)
		return true;

	/* Need a modifiable copy */
	rawstring = pstrdup(slist);

	/* Parse string into list of syscalls */
	if (!SplitIdentifierString(rawstring, ',', &elemlist))
	{
		result = false;
		goto out;
	}

	/* add syscall specific rules to the filter */
	foreach(l, elemlist)
	{
		char   *cursyscall = (char *) lfirst(l);
		int		syscallnum;
		int		rc;

		/*
		 * Resolve the syscall name to its number on the current arch.
		 * This should have already been validated by the GUC
		 * check function.
		 */
		syscallnum = seccomp_syscall_resolve_name(cursyscall);
		if (syscallnum < 0)
		{
			/* should not happen */
			ereport(WARNING,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("seccomp failed to resolve: syscall \"%s\"",
							cursyscall)));
			result = false;
			goto out;
		}
		else
		{
			rc = seccomp_rule_add(*ctx, rule_action, syscallnum, 0);
			if (rc != 0)
			{
				/* should not be reachable */
				ereport(WARNING,
						(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
						 errmsg("seccomp failed to add rule: syscall \"%s\", %d",
								 cursyscall, syscallnum)));
				result = false;
				goto out;
			}
			oldcontext = MemoryContextSwitchTo(TopMemoryContext);

			if (rule_action == SCMP_ACT_ALLOW)
				current_filter->allow = bms_add_member(current_filter->allow,
													   syscallnum);
			else if (rule_action == SCMP_ACT_LOG)
				current_filter->log = bms_add_member(current_filter->log,
													   syscallnum);
			else if (rule_action == SCMP_ACT_ERRNO(EACCES))
				current_filter->error = bms_add_member(current_filter->error,
													   syscallnum);
			else if (rule_action == SCMP_ACT_KILL)
				current_filter->kill = bms_add_member(current_filter->kill,
													   syscallnum);

			MemoryContextSwitchTo(oldcontext);
		}
	}

out:
	/* safe to release if still NIL */
	list_free(elemlist);

	/* but pfree is not */
	if (rawstring)
		pfree(rawstring);

	return result;
}

static char*
expand_seccomp_list(char *slist, char *glist, char *saction)
{
	
	if (slist && strlen(slist) == 1 && slist[0] == '*')
	{
		/* use the global list as promised */
		ereport(LOG,
				(errmsg("seccomp \"%s\" list inherited from postmaster", saction)));

		return glist;
	}
	else
		return slist;
}

static void
set_filter_def_action(int default_action, seccomp_filter *current_filter,
					  char *context)
{
	current_filter->def = default_action;
	ereport(LOG,
			(errmsg("seccomp default action set to \"%s\": context \"%s\"",
					get_seccomp_opt_str(default_action), context)));
}

PG_FUNCTION_INFO_V1(pg_set_client_filter);
Datum
pg_set_client_filter(PG_FUNCTION_ARGS)
{
	/* We only want to allow one client level filter */
	if (client_filter_loaded)
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("Client filter may only be loaded once")));

	/*
	 * If any of the args are NULL, just substitute
	 * the value of the corresponding session var.
	 */
	if (PG_ARGISNULL(0))
		client_syscall_default = session_syscall_default;
	else
	{
		int	rc = get_seccomp_opt_num(text_to_cstring(PG_GETARG_TEXT_PP(0)));

		if (rc >= PG_SECCOMP_ALLOW && rc <= PG_SECCOMP_KILL)
			client_syscall_default = rc;
		else
			ereport(ERROR,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("Default action not valid"),
					 errhint("Must be \"allow\", \"log\", \"error\", or \"kill\".")));
	}

	if (PG_ARGISNULL(1))
		client_syscall_allow_string = session_syscall_allow_string;
	else
		client_syscall_allow_string = text_to_cstring(PG_GETARG_TEXT_PP(1));

	if (PG_ARGISNULL(2))
		client_syscall_log_string = session_syscall_log_string;
	else
		client_syscall_log_string = text_to_cstring(PG_GETARG_TEXT_PP(2));

	if (PG_ARGISNULL(3))
		client_syscall_error_string = session_syscall_error_string;
	else
		client_syscall_error_string = text_to_cstring(PG_GETARG_TEXT_PP(3));

	if (PG_ARGISNULL(4))
		client_syscall_kill_string = session_syscall_kill_string;
	else
		client_syscall_kill_string = text_to_cstring(PG_GETARG_TEXT_PP(4));

	/* Now expand any wildcards to the global list */
	client_syscall_allow_string = expand_seccomp_list(client_syscall_allow_string,
													  global_syscall_allow_string,
													  "allow");
	client_syscall_log_string = expand_seccomp_list(client_syscall_log_string,
													global_syscall_log_string,
													"log");
	client_syscall_error_string = expand_seccomp_list(client_syscall_error_string,
													  global_syscall_error_string,
													  "error");
	client_syscall_kill_string = expand_seccomp_list(client_syscall_kill_string,
													 global_syscall_kill_string,
													 "kill");

	if(!load_seccomp_filter("client"))
	{
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("failed to load client seccomp filter")));
	}

	client_filter_loaded = true;
	PG_RETURN_TEXT_P(cstring_to_text("OK"));
}
