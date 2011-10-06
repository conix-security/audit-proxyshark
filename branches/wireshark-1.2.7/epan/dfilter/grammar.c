/* Driver template for the LEMON parser generator.
* $Id: lempar.c 28662 2009-06-08 15:37:46Z gerald $
*
** Copyright 1991-1995 by D. Richard Hipp.
**
** This library is free software; you can redistribute it and/or
** modify it under the terms of the GNU Library General Public
** License as published by the Free Software Foundation; either
** version 2 of the License, or (at your option) any later version.
**
** This library is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
** Library General Public License for more details.
**
** You should have received a copy of the GNU Library General Public
** License along with this library; if not, write to the
** Free Software Foundation, Inc., 59 Temple Place - Suite 330,
** Boston, MA  02111-1307, USA.
**
** Modified 1997 to make it suitable for use with makeheaders.
* Updated to sqlite lemon version 1.36
*/
/* First off, code is included that follows the "include" declaration
** in the input grammar file. */
#line 3 "./grammar.lemon"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dfilter-int.h"
#include "syntax-tree.h"
#include "sttype-range.h"
#include "sttype-test.h"
#include "sttype-function.h"
#include "drange.h"

#include "grammar.h"

#ifdef _WIN32
#pragma warning(disable:4671)
#endif
	
/* End of C code */
#line 49 "grammar.c"
#include <stdio.h>
#include <string.h>
/* Next is all token values, in a form suitable for use by makeheaders.
** This section will be null unless lemon is run with the -m switch.
*/
/*
** These constants (all generated automatically by the parser generator)
** specify the various kinds of tokens (terminals) that the parser
** understands.
**
** Each symbol here is a terminal symbol in the grammar.
*/
/* Make sure the INTERFACE macro is defined.
*/
#ifndef INTERFACE
# define INTERFACE 1
#endif
/* The next thing included is series of defines which control
** various aspects of the generated parser.
**    YYCODETYPE         is the data type used for storing terminal
**                       and nonterminal numbers.  "unsigned char" is
**                       used if there are fewer than 250 terminals
**                       and nonterminals.  "int" is used otherwise.
**    YYNOCODE           is a number of type YYCODETYPE which corresponds
**                       to no legal terminal or nonterminal number.  This
**                       number is used to fill in empty slots of the hash
**                       table.
**    YYFALLBACK         If defined, this indicates that one or more tokens
**                       have fall-back values which should be used if the
**                       original value of the token will not parse.
**    YYACTIONTYPE       is the data type used for storing terminal
**                       and nonterminal numbers.  "unsigned char" is
**                       used if there are fewer than 250 rules and
**                       states combined.  "int" is used otherwise.
**    DfilterTOKENTYPE     is the data type used for minor tokens given
**                       directly to the parser from the tokenizer.
**    YYMINORTYPE        is the data type used for all minor tokens.
**                       This is typically a union of many types, one of
**                       which is DfilterTOKENTYPE.  The entry in the union
**                       for base tokens is called "yy0".
**    YYSTACKDEPTH       is the maximum depth of the parser's stack.  If
**                       zero the stack is dynamically sized using realloc()
**    DfilterARG_SDECL     A static variable declaration for the %extra_argument
**    DfilterARG_PDECL     A parameter declaration for the %extra_argument
**    DfilterARG_STORE     Code to store %extra_argument into yypParser
**    DfilterARG_FETCH     Code to extract %extra_argument from yypParser
**    YYNSTATE           the combined number of states.
**    YYNRULE            the number of rules in the grammar
**    YYERRORSYMBOL      is the code number of the error symbol.  If not
**                       defined, then do no error processing.
*/
#define YYCODETYPE signed char
#define YYNOCODE 37
#define YYACTIONTYPE signed char
#define DfilterTOKENTYPE stnode_t*
typedef union {
  DfilterTOKENTYPE yy0;
  drange_node* yy5;
  GSList* yy33;
  test_op_t yy62;
  int yy73;
} YYMINORTYPE;
#ifndef YYSTACKDEPTH
#define YYSTACKDEPTH 100
#endif
#define DfilterARG_SDECL dfwork_t *dfw;
#define DfilterARG_PDECL ,dfwork_t *dfw
#define DfilterARG_FETCH dfwork_t *dfw = yypParser->dfw
#define DfilterARG_STORE yypParser->dfw = dfw
#define YYNSTATE 50
#define YYNRULE 35
#define YYERRORSYMBOL 25
#define YYERRSYMDT yy73
#define YY_NO_ACTION      (YYNSTATE+YYNRULE+2)
#define YY_ACCEPT_ACTION  (YYNSTATE+YYNRULE+1)
#define YY_ERROR_ACTION   (YYNSTATE+YYNRULE)

/* The yyzerominor constant is used to initialize instances of
** YYMINORTYPE objects to zero. */
static const YYMINORTYPE yyzerominor;

/* Next are the tables used to determine what action to take based on the
** current state and lookahead token.  These tables are used to implement
** functions that take a state number and lookahead value and return an
** action integer.  
**
** Suppose the action integer is N.  Then the action is determined as
** follows
**
**   0 <= N < YYNSTATE                  Shift N.  That is, push the lookahead
**                                      token onto the stack and goto state N.
**
**   YYNSTATE <= N < YYNSTATE+YYNRULE   Reduce by rule N-YYNSTATE.
**
**   N == YYNSTATE+YYNRULE              A syntax error has occurred.
**
**   N == YYNSTATE+YYNRULE+1            The parser accepts its input.
**
**   N == YYNSTATE+YYNRULE+2            No such action.  Denotes unused
**                                      slots in the yy_action[] table.
**
** The action table is constructed as a single large table named yy_action[].
** Given state S and lookahead X, the action is computed as
**
**      yy_action[ yy_shift_ofst[S] + X ]
**
** If the index value yy_shift_ofst[S]+X is out of range or if the value
** yy_lookahead[yy_shift_ofst[S]+X] is not equal to X or if yy_shift_ofst[S]
** is equal to YY_SHIFT_USE_DFLT, it means that the action is not in the table
** and that yy_default[S] should be used instead.  
**
** The formula above is for computing the action when the lookahead is
** a terminal symbol.  If the lookahead is a non-terminal (as occurs after
** a reduce action) then the yy_reduce_ofst[] array is used in place of
** the yy_shift_ofst[] array and YY_REDUCE_USE_DFLT is used in place of
** YY_SHIFT_USE_DFLT.
**
** The following are the tables generated in this section:
**
**  yy_action[]        A single table containing all actions.
**  yy_lookahead[]     A table containing the lookahead for each entry in
**                     yy_action.  Used to detect hash collisions.
**  yy_shift_ofst[]    For each state, the offset into yy_action for
**                     shifting terminals.
**  yy_reduce_ofst[]   For each state, the offset into yy_action for
**                     shifting non-terminals after a reduce.
**  yy_default[]       Default action for each state.
*/
static const YYACTIONTYPE yy_action[] = {
 /*     0 */    40,   41,   44,   45,   42,   43,   47,   48,   46,   51,
 /*    10 */    86,   11,    9,   22,   23,   27,   34,    3,   17,   32,
 /*    20 */    33,    3,   17,   32,   33,    6,   35,   21,    4,    2,
 /*    30 */    34,   21,    4,   16,    9,   22,   23,    7,   34,   24,
 /*    40 */     9,   22,   23,   36,   34,   25,    9,   22,   23,    8,
 /*    50 */    34,   12,    9,   22,   23,    5,   34,   28,   17,   32,
 /*    60 */    33,   17,   32,   33,   39,    1,    2,   21,   34,   38,
 /*    70 */    21,   15,   50,    1,    2,   37,   14,   20,   29,   34,
 /*    80 */    26,   10,   31,   13,   87,   18,   19,   30,   49,
};
static const YYCODETYPE yy_lookahead[] = {
 /*     0 */     3,    4,    5,    6,    7,    8,    9,   10,   11,    0,
 /*    10 */    26,   27,   28,   29,   30,   33,   32,   12,   13,   14,
 /*    20 */    15,   12,   13,   14,   15,   31,   28,   22,   23,    2,
 /*    30 */    32,   22,   23,   27,   28,   29,   30,   18,   32,   27,
 /*    40 */    28,   29,   30,   24,   32,   27,   28,   29,   30,   16,
 /*    50 */    32,   27,   28,   29,   30,   23,   32,   19,   13,   14,
 /*    60 */    15,   13,   14,   15,   28,    1,    2,   22,   32,   24,
 /*    70 */    22,   35,    0,    1,    2,   28,   19,   20,   19,   32,
 /*    80 */    17,   18,   33,   34,   36,   20,   21,   19,   24,
};
#define YY_SHIFT_USE_DFLT (-4)
#define YY_SHIFT_MAX 21
static const signed char yy_shift_ofst[] = {
 /*     0 */     9,    5,    5,    5,    5,   45,   48,   48,   57,   -3,
 /*    10 */    57,   72,   64,   63,   65,   19,   27,   33,   38,   59,
 /*    20 */    68,   32,
};
#define YY_REDUCE_USE_DFLT (-19)
#define YY_REDUCE_MAX 10
static const signed char yy_reduce_ofst[] = {
 /*     0 */   -16,    6,   12,   18,   24,   36,   -2,   47,   49,   -6,
 /*    10 */   -18,
};
static const YYACTIONTYPE yy_default[] = {
 /*     0 */    85,   85,   85,   85,   85,   85,   85,   85,   85,   57,
 /*    10 */    85,   85,   85,   85,   69,   85,   54,   58,   68,   85,
 /*    20 */    85,   85,   52,   53,   55,   56,   62,   64,   65,   66,
 /*    30 */    67,   63,   59,   60,   61,   70,   80,   83,   81,   82,
 /*    40 */    71,   72,   73,   74,   75,   76,   77,   78,   79,   84,
};
#define YY_SZ_ACTTAB (int)(sizeof(yy_action)/sizeof(yy_action[0]))

/* The next table maps tokens into fallback tokens.  If a construct
** like the following:
** 
**      %fallback ID X Y Z.
**
** appears in the grammar, then ID becomes a fallback token for X, Y,
** and Z.  Whenever one of the tokens X, Y, or Z is input to the parser
** but it does not parse, the type of the token is changed to ID and
** the parse is retried before an error is thrown.
*/
#ifdef YYFALLBACK
static const YYCODETYPE yyFallback[] = {
};
#endif /* YYFALLBACK */

/* The following structure represents a single element of the
** parser's stack.  Information stored includes:
**
**   +  The state number for the parser at this level of the stack.
**
**   +  The value of the token stored at this level of the stack.
**      (In other words, the "major" token.)
**
**   +  The semantic value stored at this level of the stack.  This is
**      the information used by the action routines in the grammar.
**      It is sometimes called the "minor" token.
*/
struct yyStackEntry {
  YYACTIONTYPE stateno;  /* The state-number */
  YYCODETYPE major;      /* The major token value.  This is the code
                         ** number for the token at this stack level */
  YYMINORTYPE minor;     /* The user-supplied minor token value.  This
                         ** is the value of the token  */
};
typedef struct yyStackEntry yyStackEntry;

/* The state of the parser is completely contained in an instance of
** the following structure */
struct yyParser {
  int yyidx;                    /* Index of top element in stack */
#ifdef YYTRACKMAXSTACKDEPTH
  int yyidxMax;                 /* Maximum value of yyidx */
#endif
  int yyerrcnt;                 /* Shifts left before out of the error */
  DfilterARG_SDECL                /* A place to hold %extra_argument */
#if YYSTACKDEPTH<=0
  int yystksz;                  /* Current side of the stack */
  yyStackEntry *yystack;        /* The parser's stack */
#else
  yyStackEntry yystack[YYSTACKDEPTH];  /* The parser's stack */
#endif
};
typedef struct yyParser yyParser;

#ifndef NDEBUG
#include <stdio.h>
static FILE *yyTraceFILE = 0;
static char *yyTracePrompt = 0;
#endif /* NDEBUG */
 
#ifndef NDEBUG
/*
** Turn parser tracing on by giving a stream to which to write the trace
** and a prompt to preface each trace message.  Tracing is turned off
** by making either argument NULL
**
** Inputs:
** <ul>
** <li> A FILE* to which trace output should be written.
**      If NULL, then tracing is turned off.
** <li> A prefix string written at the beginning of every
**      line of trace output.  If NULL, then tracing is
**      turned off.
** </ul>
**
** Outputs:
** None.
*/
void DfilterTrace(FILE *TraceFILE, char *zTracePrompt){
  yyTraceFILE = TraceFILE;
  yyTracePrompt = zTracePrompt;
  if( yyTraceFILE==0 ) yyTracePrompt = 0;
  else if( yyTracePrompt==0 ) yyTraceFILE = 0;
}
#endif /* NDEBUG */
 
#ifndef NDEBUG
/* For tracing shifts, the names of all terminals and nonterminals
** are required.  The following table supplies these names */
static const char *const yyTokenName[] = {
  "$",             "TEST_AND",      "TEST_OR",       "TEST_EQ",     
  "TEST_NE",       "TEST_LT",       "TEST_LE",       "TEST_GT",     
  "TEST_GE",       "TEST_CONTAINS",  "TEST_MATCHES",  "TEST_BITWISE_AND",
  "TEST_NOT",      "FIELD",         "STRING",        "UNPARSED",    
  "LBRACKET",      "RBRACKET",      "COMMA",         "INTEGER",     
  "COLON",         "HYPHEN",        "FUNCTION",      "LPAREN",      
  "RPAREN",        "error",         "sentence",      "expr",        
  "entity",        "relation_test",  "logical_test",  "rel_op2",     
  "range",         "drnode",        "drnode_list",   "funcparams",  
};
#endif /* NDEBUG */

#ifndef NDEBUG
/* For tracing reduce actions, the names of all rules are required.
*/
static const char *const yyRuleName[] = {
 /*   0 */ "sentence ::= expr",
 /*   1 */ "sentence ::=",
 /*   2 */ "expr ::= relation_test",
 /*   3 */ "expr ::= logical_test",
 /*   4 */ "logical_test ::= expr TEST_AND expr",
 /*   5 */ "logical_test ::= expr TEST_OR expr",
 /*   6 */ "logical_test ::= TEST_NOT expr",
 /*   7 */ "logical_test ::= entity",
 /*   8 */ "entity ::= FIELD",
 /*   9 */ "entity ::= STRING",
 /*  10 */ "entity ::= UNPARSED",
 /*  11 */ "entity ::= range",
 /*  12 */ "range ::= FIELD LBRACKET drnode_list RBRACKET",
 /*  13 */ "drnode_list ::= drnode",
 /*  14 */ "drnode_list ::= drnode_list COMMA drnode",
 /*  15 */ "drnode ::= INTEGER COLON INTEGER",
 /*  16 */ "drnode ::= INTEGER HYPHEN INTEGER",
 /*  17 */ "drnode ::= COLON INTEGER",
 /*  18 */ "drnode ::= INTEGER COLON",
 /*  19 */ "drnode ::= INTEGER",
 /*  20 */ "relation_test ::= entity rel_op2 entity",
 /*  21 */ "rel_op2 ::= TEST_EQ",
 /*  22 */ "rel_op2 ::= TEST_NE",
 /*  23 */ "rel_op2 ::= TEST_GT",
 /*  24 */ "rel_op2 ::= TEST_GE",
 /*  25 */ "rel_op2 ::= TEST_LT",
 /*  26 */ "rel_op2 ::= TEST_LE",
 /*  27 */ "rel_op2 ::= TEST_BITWISE_AND",
 /*  28 */ "rel_op2 ::= TEST_CONTAINS",
 /*  29 */ "rel_op2 ::= TEST_MATCHES",
 /*  30 */ "entity ::= FUNCTION LPAREN funcparams RPAREN",
 /*  31 */ "entity ::= FUNCTION LPAREN RPAREN",
 /*  32 */ "funcparams ::= entity",
 /*  33 */ "funcparams ::= funcparams COMMA entity",
 /*  34 */ "expr ::= LPAREN expr RPAREN",
};
#endif /* NDEBUG */


#if YYSTACKDEPTH<=0
/*
** Try to increase the size of the parser stack.
*/
static void yyGrowStack(yyParser *p){
  int newSize;
  yyStackEntry *pNew;

  newSize = p->yystksz*2 + 100;
  pNew = realloc(p->yystack, newSize*sizeof(pNew[0]));
  if( pNew ){
    p->yystack = pNew;
    p->yystksz = newSize;
#ifndef NDEBUG
    if( yyTraceFILE ){
      fprintf(yyTraceFILE,"%sStack grows to %d entries!\n",
              yyTracePrompt, p->yystksz);
    }
#endif
  }
}
#endif

/*
** This function allocates a new parser.
** The only argument is a pointer to a function which works like
** malloc.
**
** Inputs:
** A pointer to the function used to allocate memory.
**
** Outputs:
** A pointer to a parser.  This pointer is used in subsequent calls
** to Dfilter and DfilterFree.
*/
#if GLIB_CHECK_VERSION(2,16,0)
void *DfilterAlloc(void *(*mallocProc)(gsize)){
  yyParser *pParser;
  pParser = (yyParser*)(*mallocProc)( (gsize)sizeof(yyParser) );
#else
void *DfilterAlloc(void *(*mallocProc)(gulong)){
  yyParser *pParser;
  pParser = (yyParser*)(*mallocProc)( (gulong)sizeof(yyParser) );
#endif
  if( pParser ){
    pParser->yyidx = -1;
#ifdef YYTRACKMAXSTACKDEPTH
    pParser->yyidxMax = 0;
#endif
#if YYSTACKDEPTH<=0
    yyGrowStack(pParser);
#endif
  }
  return pParser;
}

/* The following function deletes the value associated with a
** symbol.  The symbol can be either a terminal or nonterminal.
** "yymajor" is the symbol code, and "yypminor" is a pointer to
** the value.
*/
static void yy_destructor(YYCODETYPE yymajor, YYMINORTYPE *yypminor){
  switch( yymajor ){
    /* Here is inserted the actions which take place when a
    ** terminal or non-terminal is destroyed.  This can happen
    ** when the symbol is popped from the stack during a
    ** reduce or during error processing or when a parser is
    ** being destroyed before it is finished parsing.
    **
    ** Note: during a reduce, the only symbols destroyed are those
    ** which appear on the RHS of the rule, but which are not used
    ** inside the C code.
    */
      /* TERMINAL Destructor */
    case 1: /* TEST_AND */
    case 2: /* TEST_OR */
    case 3: /* TEST_EQ */
    case 4: /* TEST_NE */
    case 5: /* TEST_LT */
    case 6: /* TEST_LE */
    case 7: /* TEST_GT */
    case 8: /* TEST_GE */
    case 9: /* TEST_CONTAINS */
    case 10: /* TEST_MATCHES */
    case 11: /* TEST_BITWISE_AND */
    case 12: /* TEST_NOT */
    case 13: /* FIELD */
    case 14: /* STRING */
    case 15: /* UNPARSED */
    case 16: /* LBRACKET */
    case 17: /* RBRACKET */
    case 18: /* COMMA */
    case 19: /* INTEGER */
    case 20: /* COLON */
    case 21: /* HYPHEN */
    case 22: /* FUNCTION */
    case 23: /* LPAREN */
    case 24: /* RPAREN */
{
#line 31 "./grammar.lemon"
stnode_free((yypminor->yy0));
#line 469 "grammar.c"
}
      break;
    case 27: /* expr */
    case 28: /* entity */
    case 29: /* relation_test */
    case 30: /* logical_test */
    case 32: /* range */
{
#line 37 "grammar.c"
stnode_free((yypminor->yy0));
#line 480 "grammar.c"
}
      break;
    case 33: /* drnode */
{
#line 54 "grammar.c"
drange_node_free((yypminor->yy5));
#line 487 "grammar.c"
}
      break;
    case 34: /* drnode_list */
{
#line 57 "grammar.c"
drange_node_free_list((yypminor->yy33));
#line 494 "grammar.c"
}
      break;
    case 35: /* funcparams */
{
#line 60 "grammar.c"
st_funcparams_free((yypminor->yy33));
#line 501 "grammar.c"
}
      break;
    default:  break;   /* If no destructor action specified: do nothing */
  }
}

/*
** Pop the parser's stack once.
**
** If there is a destructor routine associated with the token which
** is popped from the stack, then call it.
**
** Return the major token number for the symbol popped.
*/
static int yy_pop_parser_stack(yyParser *pParser){
  YYCODETYPE yymajor;
  yyStackEntry *yytos = &pParser->yystack[pParser->yyidx];

  if( pParser->yyidx<0 ) return 0;
#ifndef NDEBUG
  if( yyTraceFILE && pParser->yyidx>=0 ){
    fprintf(yyTraceFILE,"%sPopping %s\n",
      yyTracePrompt,
     yyTokenName[yytos->major]);
  }
#endif
  yymajor = yytos->major;
  yy_destructor( yymajor, &yytos->minor);
  pParser->yyidx--;
  return yymajor;
}

/*
** Deallocate and destroy a parser.  Destructors are all called for
** all stack elements before shutting the parser down.
**
** Inputs:
** <ul>
** <li>  A pointer to the parser.  This should be a pointer
**       obtained from DfilterAlloc.
** <li>  A pointer to a function used to reclaim memory obtained
**       from malloc.
** </ul>
*/
void DfilterFree(
  void *p,                 /* The parser to be deleted */
  void (*freeProc)(void*)  /* Function used to reclaim memory */
){
  yyParser *pParser = (yyParser*)p;
  if( pParser==0 ) return;
  while( pParser->yyidx>=0 ) yy_pop_parser_stack(pParser);
#if YYSTACKDEPTH<=0
  free(pParser->yystack);
#endif
  (*freeProc)(pParser);
}

/*
** Return the peak depth of the stack for a parser.
*/
#ifdef YYTRACKMAXSTACKDEPTH
int DfilterStackPeak(void *p){
  yyParser *pParser = (yyParser*)p;
  return pParser->yyidxMax;
}
#endif

/*
** Find the appropriate action for a parser given the terminal
** look-ahead token iLookAhead.
**
** If the look-ahead token is YYNOCODE, then check to see if the action is
** independent of the look-ahead.  If it is, return the action, otherwise
** return YY_NO_ACTION.
*/
static int yy_find_shift_action(
  yyParser *pParser,        /* The parser */
  YYCODETYPE iLookAhead     /* The look-ahead token */
){
  int i;
  int stateno = pParser->yystack[pParser->yyidx].stateno;

  if( stateno>YY_SHIFT_MAX || (i = yy_shift_ofst[stateno])==YY_SHIFT_USE_DFLT ){
    return yy_default[stateno];
  }
  assert( iLookAhead!=YYNOCODE );
  i += iLookAhead;
  if( i<0 || i>=YY_SZ_ACTTAB || yy_lookahead[i]!=iLookAhead ){
    if( iLookAhead>0 ){
#ifdef YYFALLBACK
      int iFallback;            /* Fallback token */
      if( iLookAhead<sizeof(yyFallback)/sizeof(yyFallback[0])
             && (iFallback = yyFallback[iLookAhead])!=0 ){
#ifndef NDEBUG
        if( yyTraceFILE ){
          fprintf(yyTraceFILE, "%sFALLBACK %s => %s\n",
             yyTracePrompt, yyTokenName[iLookAhead], yyTokenName[iFallback]);
        }
#endif
        return yy_find_shift_action(pParser, iFallback);
      }
#endif
#ifdef YYWILDCARD
	  {
      int j = i - iLookAhead + YYWILDCARD;
      if( j>=0 && j<YY_SZ_ACTTAB && yy_lookahead[j]==YYWILDCARD ){
#ifndef NDEBUG
        if( yyTraceFILE ){
          fprintf(yyTraceFILE, "%sWILDCARD %s => %s\n",
             yyTracePrompt, yyTokenName[iLookAhead], yyTokenName[YYWILDCARD]);
        }
#endif /* NDEBUG */
        return yy_action[j];
      }
	  }
#endif /* YYWILDCARD */
    }
    return yy_default[stateno];
  }else{
    return yy_action[i];
  }
}

/*
** Find the appropriate action for a parser given the non-terminal
** look-ahead token iLookAhead.
**
** If the look-ahead token is YYNOCODE, then check to see if the action is
** independent of the look-ahead.  If it is, return the action, otherwise
** return YY_NO_ACTION.
*/
static int yy_find_reduce_action(
  int stateno,              /* Current state number */
  YYCODETYPE iLookAhead     /* The look-ahead token */
){
  int i;
#ifdef YYERRORSYMBOL
  if( stateno>YY_REDUCE_MAX ){
    return yy_default[stateno];
  }
#else
  assert( stateno<=YY_REDUCE_MAX );
#endif
  i = yy_reduce_ofst[stateno];
  assert( i!=YY_REDUCE_USE_DFLT );
  assert( iLookAhead!=YYNOCODE );
  i += iLookAhead;
#ifdef YYERRORSYMBOL
  if( i<0 || i>=YY_SZ_ACTTAB || yy_lookahead[i]!=iLookAhead ){
    return yy_default[stateno];
  }
#else
  assert( i>=0 && i<YY_SZ_ACTTAB );
  assert( yy_lookahead[i]==iLookAhead );
#endif
  return yy_action[i];
}

/*
** The following routine is called if the stack overflows.
*/
static void yyStackOverflow(yyParser *yypParser, YYMINORTYPE *yypMinor _U_){
   DfilterARG_FETCH;
   yypParser->yyidx--;
#ifndef NDEBUG
   if( yyTraceFILE ){
     fprintf(yyTraceFILE,"%sStack Overflow!\n",yyTracePrompt);
   }
#endif
   while( yypParser->yyidx>=0 ) yy_pop_parser_stack(yypParser);
   /* Here code is inserted which will execute if the parser
   ** stack every overflows */
   DfilterARG_STORE; /* Suppress warning about unused %extra_argument var */
}

/*
** Perform a shift action.
*/
static void yy_shift(
  yyParser *yypParser,          /* The parser to be shifted */
  int yyNewState,               /* The new state to shift in */
  int yyMajor,                  /* The major token to shift in */
  YYMINORTYPE *yypMinor         /* Pointer to the minor token to shift in */
){
  yyStackEntry *yytos;
  yypParser->yyidx++;
#ifdef YYTRACKMAXSTACKDEPTH
  if( yypParser->yyidx>yypParser->yyidxMax ){
    yypParser->yyidxMax = yypParser->yyidx;
  }
#endif
#if YYSTACKDEPTH>0
  if( yypParser->yyidx>=YYSTACKDEPTH ){
    yyStackOverflow(yypParser, yypMinor);
    return;
  }
#else
  if( yypParser->yyidx>=yypParser->yystksz ){
    yyGrowStack(yypParser);
    if( yypParser->yyidx>=yypParser->yystksz ){
      yyStackOverflow(yypParser, yypMinor);
      return;
    }
  }
#endif
  yytos = &yypParser->yystack[yypParser->yyidx];
  yytos->stateno = yyNewState;
  yytos->major = yyMajor;
  yytos->minor = *yypMinor;
#ifndef NDEBUG
  if( yyTraceFILE && yypParser->yyidx>0 ){
    int i;
    fprintf(yyTraceFILE,"%sShift %d\n",yyTracePrompt,yyNewState);
    fprintf(yyTraceFILE,"%sStack:",yyTracePrompt);
    for(i=1; i<=yypParser->yyidx; i++)
      fprintf(yyTraceFILE," %s",yyTokenName[yypParser->yystack[i].major]);
    fprintf(yyTraceFILE,"\n");
  }
#endif
}

/* The following table contains information about every rule that
** is used during the reduce.
*/
static const struct {
  YYCODETYPE lhs;         /* Symbol on the left-hand side of the rule */
  unsigned char nrhs;     /* Number of right-hand side symbols in the rule */
} yyRuleInfo[] = {
  { 26, 1 },
  { 26, 0 },
  { 27, 1 },
  { 27, 1 },
  { 30, 3 },
  { 30, 3 },
  { 30, 2 },
  { 30, 1 },
  { 28, 1 },
  { 28, 1 },
  { 28, 1 },
  { 28, 1 },
  { 32, 4 },
  { 34, 1 },
  { 34, 3 },
  { 33, 3 },
  { 33, 3 },
  { 33, 2 },
  { 33, 2 },
  { 33, 1 },
  { 29, 3 },
  { 31, 1 },
  { 31, 1 },
  { 31, 1 },
  { 31, 1 },
  { 31, 1 },
  { 31, 1 },
  { 31, 1 },
  { 31, 1 },
  { 31, 1 },
  { 28, 4 },
  { 28, 3 },
  { 35, 1 },
  { 35, 3 },
  { 27, 3 },
};

static void yy_accept(yyParser *yypParser);  /* Forward declaration */

/*
** Perform a reduce action and the shift that must immediately
** follow the reduce.
*/
static void yy_reduce(
  yyParser *yypParser,         /* The parser */
  int yyruleno                 /* Number of the rule by which to reduce */
){
  int yygoto;                     /* The next state */
  int yyact;                      /* The next action */
  YYMINORTYPE yygotominor;        /* The LHS of the rule reduced */
  yyStackEntry *yymsp;            /* The top of the parser's stack */
  int yysize;                     /* Amount to pop the stack */
  DfilterARG_FETCH;
  yymsp = &yypParser->yystack[yypParser->yyidx];
#ifndef NDEBUG
  if( yyTraceFILE && yyruleno>=0 
        && yyruleno<(int)(sizeof(yyRuleName)/sizeof(yyRuleName[0])) ){
    fprintf(yyTraceFILE, "%sReduce [%s].\n", yyTracePrompt,
      yyRuleName[yyruleno]);
  }
#endif /* NDEBUG */

  /* Silence complaints from purify about yygotominor being uninitialized
  ** in some cases when it is copied into the stack after the following
  ** switch.  yygotominor is uninitialized when a rule reduces that does
  ** not set the value of its left-hand side nonterminal.  Leaving the
  ** value of the nonterminal uninitialized is utterly harmless as long
  ** as the value is never used.  So really the only thing this code
  ** accomplishes is to quieten purify.  
  **
  ** 2007-01-16:  The wireshark project (www.wireshark.org) reports that
  ** without this code, their parser segfaults.  I'm not sure what there
  ** parser is doing to make this happen.  This is the second bug report
  ** from wireshark this week.  Clearly they are stressing Lemon in ways
  ** that it has not been previously stressed...  (SQLite ticket #2172)
  */
  /*memset(&yygotominor, 0, sizeof(yygotominor));*/
  yygotominor = yyzerominor;
  switch( yyruleno ){
  /* Beginning here are the reduction cases.  A typical example
  ** follows:
  **   case 0:
  **  #line <lineno> <grammarfile>
  **     { ... }           // User supplied code
  **  #line <lineno> <thisfile>
  **     break;
  */
      case 0: /* sentence ::= expr */
#line 128 "./grammar.lemon"
{ dfw->st_root = yymsp[0].minor.yy0; }
#line 819 "grammar.c"
        break;
      case 1: /* sentence ::= */
#line 129 "./grammar.lemon"
{ dfw->st_root = NULL; }
#line 824 "grammar.c"
        break;
      case 2: /* expr ::= relation_test */
      case 3: /* expr ::= logical_test */
      case 8: /* entity ::= FIELD */
      case 9: /* entity ::= STRING */
      case 10: /* entity ::= UNPARSED */
      case 11: /* entity ::= range */
#line 131 "./grammar.lemon"
{ yygotominor.yy0 = yymsp[0].minor.yy0; }
#line 834 "grammar.c"
        break;
      case 4: /* logical_test ::= expr TEST_AND expr */
#line 137 "./grammar.lemon"
{
	yygotominor.yy0 = stnode_new(STTYPE_TEST, NULL);
	sttype_test_set2(yygotominor.yy0, TEST_OP_AND, yymsp[-2].minor.yy0, yymsp[0].minor.yy0);
  yy_destructor(1,&yymsp[-1].minor);
}
#line 843 "grammar.c"
        break;
      case 5: /* logical_test ::= expr TEST_OR expr */
#line 143 "./grammar.lemon"
{
	yygotominor.yy0 = stnode_new(STTYPE_TEST, NULL);
	sttype_test_set2(yygotominor.yy0, TEST_OP_OR, yymsp[-2].minor.yy0, yymsp[0].minor.yy0);
  yy_destructor(2,&yymsp[-1].minor);
}
#line 852 "grammar.c"
        break;
      case 6: /* logical_test ::= TEST_NOT expr */
#line 149 "./grammar.lemon"
{
	yygotominor.yy0 = stnode_new(STTYPE_TEST, NULL);
	sttype_test_set1(yygotominor.yy0, TEST_OP_NOT, yymsp[0].minor.yy0);
  yy_destructor(12,&yymsp[-1].minor);
}
#line 861 "grammar.c"
        break;
      case 7: /* logical_test ::= entity */
#line 155 "./grammar.lemon"
{
	yygotominor.yy0 = stnode_new(STTYPE_TEST, NULL);
	sttype_test_set1(yygotominor.yy0, TEST_OP_EXISTS, yymsp[0].minor.yy0);
}
#line 869 "grammar.c"
        break;
      case 12: /* range ::= FIELD LBRACKET drnode_list RBRACKET */
#line 171 "./grammar.lemon"
{
	yygotominor.yy0 = stnode_new(STTYPE_RANGE, NULL);
	sttype_range_set(yygotominor.yy0, yymsp[-3].minor.yy0, yymsp[-1].minor.yy33);

	/* Delete the list, but not the drange_nodes that
	 * the list contains. */
	g_slist_free(yymsp[-1].minor.yy33);
  yy_destructor(16,&yymsp[-2].minor);
  yy_destructor(17,&yymsp[0].minor);
}
#line 883 "grammar.c"
        break;
      case 13: /* drnode_list ::= drnode */
#line 181 "./grammar.lemon"
{
	yygotominor.yy33 = g_slist_append(NULL, yymsp[0].minor.yy5);
}
#line 890 "grammar.c"
        break;
      case 14: /* drnode_list ::= drnode_list COMMA drnode */
#line 186 "./grammar.lemon"
{
	yygotominor.yy33 = g_slist_append(yymsp[-2].minor.yy33, yymsp[0].minor.yy5);
  yy_destructor(18,&yymsp[-1].minor);
}
#line 898 "grammar.c"
        break;
      case 15: /* drnode ::= INTEGER COLON INTEGER */
#line 192 "./grammar.lemon"
{
	yygotominor.yy5 = drange_node_new();
	drange_node_set_start_offset(yygotominor.yy5, stnode_value(yymsp[-2].minor.yy0));
	drange_node_set_length(yygotominor.yy5, stnode_value(yymsp[0].minor.yy0));
	
	stnode_free(yymsp[-2].minor.yy0);
	stnode_free(yymsp[0].minor.yy0);
  yy_destructor(20,&yymsp[-1].minor);
}
#line 911 "grammar.c"
        break;
      case 16: /* drnode ::= INTEGER HYPHEN INTEGER */
#line 203 "./grammar.lemon"
{
	yygotominor.yy5 = drange_node_new();
	drange_node_set_start_offset(yygotominor.yy5, stnode_value(yymsp[-2].minor.yy0));
	drange_node_set_end_offset(yygotominor.yy5, stnode_value(yymsp[0].minor.yy0));
	
	stnode_free(yymsp[-2].minor.yy0);
	stnode_free(yymsp[0].minor.yy0);
  yy_destructor(21,&yymsp[-1].minor);
}
#line 924 "grammar.c"
        break;
      case 17: /* drnode ::= COLON INTEGER */
#line 215 "./grammar.lemon"
{
	yygotominor.yy5 = drange_node_new();
	drange_node_set_start_offset(yygotominor.yy5, 0);
	drange_node_set_length(yygotominor.yy5, stnode_value(yymsp[0].minor.yy0));

	stnode_free(yymsp[0].minor.yy0);
  yy_destructor(20,&yymsp[-1].minor);
}
#line 936 "grammar.c"
        break;
      case 18: /* drnode ::= INTEGER COLON */
#line 225 "./grammar.lemon"
{
	yygotominor.yy5 = drange_node_new();
	drange_node_set_start_offset(yygotominor.yy5, stnode_value(yymsp[-1].minor.yy0));
	drange_node_set_to_the_end(yygotominor.yy5);

	stnode_free(yymsp[-1].minor.yy0);
  yy_destructor(20,&yymsp[0].minor);
}
#line 948 "grammar.c"
        break;
      case 19: /* drnode ::= INTEGER */
#line 235 "./grammar.lemon"
{
	yygotominor.yy5 = drange_node_new();
	drange_node_set_start_offset(yygotominor.yy5, stnode_value(yymsp[0].minor.yy0));
	drange_node_set_length(yygotominor.yy5, 1);

	stnode_free(yymsp[0].minor.yy0);
}
#line 959 "grammar.c"
        break;
      case 20: /* relation_test ::= entity rel_op2 entity */
#line 247 "./grammar.lemon"
{
	yygotominor.yy0 = stnode_new(STTYPE_TEST, NULL);
	sttype_test_set2(yygotominor.yy0, yymsp[-1].minor.yy62, yymsp[-2].minor.yy0, yymsp[0].minor.yy0);
}
#line 967 "grammar.c"
        break;
      case 21: /* rel_op2 ::= TEST_EQ */
#line 252 "./grammar.lemon"
{ yygotominor.yy62 = TEST_OP_EQ;   yy_destructor(3,&yymsp[0].minor);
}
#line 973 "grammar.c"
        break;
      case 22: /* rel_op2 ::= TEST_NE */
#line 253 "./grammar.lemon"
{ yygotominor.yy62 = TEST_OP_NE;   yy_destructor(4,&yymsp[0].minor);
}
#line 979 "grammar.c"
        break;
      case 23: /* rel_op2 ::= TEST_GT */
#line 254 "./grammar.lemon"
{ yygotominor.yy62 = TEST_OP_GT;   yy_destructor(7,&yymsp[0].minor);
}
#line 985 "grammar.c"
        break;
      case 24: /* rel_op2 ::= TEST_GE */
#line 255 "./grammar.lemon"
{ yygotominor.yy62 = TEST_OP_GE;   yy_destructor(8,&yymsp[0].minor);
}
#line 991 "grammar.c"
        break;
      case 25: /* rel_op2 ::= TEST_LT */
#line 256 "./grammar.lemon"
{ yygotominor.yy62 = TEST_OP_LT;   yy_destructor(5,&yymsp[0].minor);
}
#line 997 "grammar.c"
        break;
      case 26: /* rel_op2 ::= TEST_LE */
#line 257 "./grammar.lemon"
{ yygotominor.yy62 = TEST_OP_LE;   yy_destructor(6,&yymsp[0].minor);
}
#line 1003 "grammar.c"
        break;
      case 27: /* rel_op2 ::= TEST_BITWISE_AND */
#line 258 "./grammar.lemon"
{ yygotominor.yy62 = TEST_OP_BITWISE_AND;   yy_destructor(11,&yymsp[0].minor);
}
#line 1009 "grammar.c"
        break;
      case 28: /* rel_op2 ::= TEST_CONTAINS */
#line 259 "./grammar.lemon"
{ yygotominor.yy62 = TEST_OP_CONTAINS;   yy_destructor(9,&yymsp[0].minor);
}
#line 1015 "grammar.c"
        break;
      case 29: /* rel_op2 ::= TEST_MATCHES */
#line 260 "./grammar.lemon"
{ yygotominor.yy62 = TEST_OP_MATCHES;   yy_destructor(10,&yymsp[0].minor);
}
#line 1021 "grammar.c"
        break;
      case 30: /* entity ::= FUNCTION LPAREN funcparams RPAREN */
#line 267 "./grammar.lemon"
{
    yygotominor.yy0 = yymsp[-3].minor.yy0;
	sttype_function_set_params(yygotominor.yy0, yymsp[-1].minor.yy33);
  yy_destructor(23,&yymsp[-2].minor);
  yy_destructor(24,&yymsp[0].minor);
}
#line 1031 "grammar.c"
        break;
      case 31: /* entity ::= FUNCTION LPAREN RPAREN */
#line 274 "./grammar.lemon"
{
    yygotominor.yy0 = yymsp[-2].minor.yy0;
  yy_destructor(23,&yymsp[-1].minor);
  yy_destructor(24,&yymsp[0].minor);
}
#line 1040 "grammar.c"
        break;
      case 32: /* funcparams ::= entity */
#line 279 "./grammar.lemon"
{
	yygotominor.yy33 = g_slist_append(NULL, yymsp[0].minor.yy0);
}
#line 1047 "grammar.c"
        break;
      case 33: /* funcparams ::= funcparams COMMA entity */
#line 284 "./grammar.lemon"
{
	yygotominor.yy33 = g_slist_append(yymsp[-2].minor.yy33, yymsp[0].minor.yy0);
  yy_destructor(18,&yymsp[-1].minor);
}
#line 1055 "grammar.c"
        break;
      case 34: /* expr ::= LPAREN expr RPAREN */
#line 291 "./grammar.lemon"
{
	yygotominor.yy0 = yymsp[-1].minor.yy0;
  yy_destructor(23,&yymsp[-2].minor);
  yy_destructor(24,&yymsp[0].minor);
}
#line 1064 "grammar.c"
        break;
  };
  yygoto = yyRuleInfo[yyruleno].lhs;
  yysize = yyRuleInfo[yyruleno].nrhs;
  yypParser->yyidx -= yysize;
  yyact = yy_find_reduce_action(yymsp[-yysize].stateno,(YYCODETYPE)yygoto);
  if( yyact < YYNSTATE ){
#ifdef NDEBUG
    /* If we are not debugging and the reduce action popped at least
    ** one element off the stack, then we can push the new element back
    ** onto the stack here, and skip the stack overflow test in yy_shift().
    ** That gives a significant speed improvement. */
    if( yysize ){
      yypParser->yyidx++;
      yymsp -= yysize-1;
      yymsp->stateno = yyact;
      yymsp->major = yygoto;
      yymsp->minor = yygotominor;
    }else
#endif
    {
      yy_shift(yypParser,yyact,yygoto,&yygotominor);
    }
  }else{
    assert( yyact == YYNSTATE + YYNRULE + 1 );
    yy_accept(yypParser);
  }
}

/*
** The following code executes when the parse fails
*/
static void yy_parse_failed(
  yyParser *yypParser           /* The parser */
){
  DfilterARG_FETCH;
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sFail!\n",yyTracePrompt);
  }
#endif
  while( yypParser->yyidx>=0 ) yy_pop_parser_stack(yypParser);
  /* Here code is inserted which will be executed whenever the
  ** parser fails */
#line 115 "./grammar.lemon"

	dfw->syntax_error = TRUE;
#line 1114 "grammar.c"
  DfilterARG_STORE; /* Suppress warning about unused %extra_argument variable */
}

/*
** The following code executes when a syntax error first occurs.
*/
static void yy_syntax_error(
  yyParser *yypParser _U_,       /* The parser */
  int yymajor _U_,               /* The major type of the error token */
  YYMINORTYPE yyminor            /* The minor type of the error token */
){
  DfilterARG_FETCH;
#define TOKEN (yyminor.yy0)
#line 64 "./grammar.lemon"


	header_field_info	*hfinfo;

	if (!TOKEN) {
		dfilter_fail("Unexpected end of filter string.");
		return;
	}

	switch(stnode_type_id(TOKEN)) {
	        case STTYPE_UNINITIALIZED:
			dfilter_fail("Syntax error.");
			break;
		case STTYPE_TEST:
			dfilter_fail("Syntax error, TEST.");
			break;
		case STTYPE_STRING:
			dfilter_fail("The string \"%s\" was unexpected in this context.",
				stnode_data(TOKEN));
			break;
		case STTYPE_UNPARSED:
			dfilter_fail("\"%s\" was unexpected in this context.",
				stnode_data(TOKEN));
			break;
		case STTYPE_INTEGER:
			dfilter_fail("The integer %d was unexpected in this context.",
				stnode_value(TOKEN));
			break;
		case STTYPE_FIELD:
			hfinfo = stnode_data(TOKEN);
			dfilter_fail("Syntax error near \"%s\".", hfinfo->abbrev);
			break;
		case STTYPE_FUNCTION:
			dfilter_fail("The function s was unexpected in this context.");
			break;

		/* These aren't handed to use as terminal tokens from
		   the scanner, so was can assert that we'll never
		   see them here. */
		case STTYPE_NUM_TYPES:
		case STTYPE_RANGE:
		case STTYPE_FVALUE:
			g_assert_not_reached();
			break;
	}
#line 1176 "grammar.c"
  DfilterARG_STORE; /* Suppress warning about unused %extra_argument variable */
}

/*
** The following is executed when the parser accepts
*/
static void yy_accept(
  yyParser *yypParser           /* The parser */
){
  DfilterARG_FETCH;
#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sAccept!\n",yyTracePrompt);
  }
#endif
  while( yypParser->yyidx>=0 ) yy_pop_parser_stack(yypParser);
  /* Here code is inserted which will be executed whenever the
  ** parser accepts */
  DfilterARG_STORE; /* Suppress warning about unused %extra_argument variable */
}

/* The main parser program.
** The first argument is a pointer to a structure obtained from
** "DfilterAlloc" which describes the current state of the parser.
** The second argument is the major token number.  The third is
** the minor token.  The fourth optional argument is whatever the
** user wants (and specified in the grammar) and is available for
** use by the action routines.
**
** Inputs:
** <ul>
** <li> A pointer to the parser (an opaque structure.)
** <li> The major token number.
** <li> The minor token number.
** <li> An option argument of a grammar-specified type.
** </ul>
**
** Outputs:
** None.
*/
void Dfilter(
  void *yyp,                   /* The parser */
  int yymajor,                 /* The major token code number */
  DfilterTOKENTYPE yyminor       /* The value for the token */
  DfilterARG_PDECL               /* Optional %extra_argument parameter */
){
  YYMINORTYPE yyminorunion;
  int yyact;            /* The parser action. */
  int yyendofinput;     /* True if we are at the end of input */
#ifdef YYERRORSYMBOL
   int yyerrorhit = 0;   /* True if yymajor has invoked an error */
#endif
  yyParser *yypParser;  /* The parser */

  /* (re)initialize the parser, if necessary */
  yypParser = (yyParser*)yyp;
  if( yypParser->yyidx<0 ){
#if YYSTACKDEPTH<=0
    if( yypParser->yystksz <=0 ){
      /*memset(&yyminorunion, 0, sizeof(yyminorunion));*/
      yyminorunion = yyzerominor;
       yyStackOverflow(yypParser, &yyminorunion);
      return;
    }
#endif
    yypParser->yyidx = 0;
    yypParser->yyerrcnt = -1;
    yypParser->yystack[0].stateno = 0;
    yypParser->yystack[0].major = 0;
  }
  yyminorunion.yy0 = yyminor;
  yyendofinput = (yymajor==0);
  DfilterARG_STORE;

#ifndef NDEBUG
  if( yyTraceFILE ){
    fprintf(yyTraceFILE,"%sInput %s\n",yyTracePrompt,yyTokenName[yymajor]);
  }
#endif

  do{
    yyact = yy_find_shift_action(yypParser,(YYCODETYPE)yymajor);
    if( yyact<YYNSTATE ){
	  assert( !yyendofinput );  /* Impossible to shift the $ token */
      yy_shift(yypParser,yyact,yymajor,&yyminorunion);
      yypParser->yyerrcnt--;
	  yymajor = YYNOCODE;
    }else if( yyact < YYNSTATE + YYNRULE ){
      yy_reduce(yypParser,yyact-YYNSTATE);
    }else{
#ifdef YYERRORSYMBOL
      int yymx;
#endif
      assert( yyact == YY_ERROR_ACTION );
#ifndef NDEBUG
      if( yyTraceFILE ){
        fprintf(yyTraceFILE,"%sSyntax Error!\n",yyTracePrompt);
      }
#endif
#ifdef YYERRORSYMBOL
      /* A syntax error has occurred.
      ** The response to an error depends upon whether or not the
      ** grammar defines an error token "ERROR".
      **
      ** This is what we do if the grammar does define ERROR:
      **
      **  * Call the %syntax_error function.
      **
      **  * Begin popping the stack until we enter a state where
      **    it is legal to shift the error symbol, then shift
      **    the error symbol.
      **
      **  * Set the error count to three.
      **
      **  * Begin accepting and shifting new tokens.  No new error
      **    processing will occur until three tokens have been
      **    shifted successfully.
      **
      */
      if( yypParser->yyerrcnt<0 ){
        yy_syntax_error(yypParser,yymajor,yyminorunion);
      }
      yymx = yypParser->yystack[yypParser->yyidx].major;
      if( yymx==YYERRORSYMBOL || yyerrorhit ){
#ifndef NDEBUG
        if( yyTraceFILE ){
          fprintf(yyTraceFILE,"%sDiscard input token %s\n",
             yyTracePrompt,yyTokenName[yymajor]);
        }
#endif
        yy_destructor((YYCODETYPE)yymajor,&yyminorunion);
        yymajor = YYNOCODE;
      }else{
         while(
          yypParser->yyidx >= 0 &&
          yymx != YYERRORSYMBOL &&
          (yyact = yy_find_reduce_action(
                        yypParser->yystack[yypParser->yyidx].stateno,
                        YYERRORSYMBOL)) >= YYNSTATE
		  ){
          yy_pop_parser_stack(yypParser);
        }
        if( yypParser->yyidx < 0 || yymajor==0 ){
          yy_destructor((YYCODETYPE)yymajor,&yyminorunion);
          yy_parse_failed(yypParser);
          yymajor = YYNOCODE;
        }else if( yymx!=YYERRORSYMBOL ){
          YYMINORTYPE u2;
          u2.YYERRSYMDT = 0;
          yy_shift(yypParser,yyact,YYERRORSYMBOL,&u2);
        }
      }
      yypParser->yyerrcnt = 3;
      yyerrorhit = 1;
#else  /* YYERRORSYMBOL is not defined */
      /* This is what we do if the grammar does not define ERROR:
      **
      **  * Report an error message, and throw away the input token.
      **
      **  * If the input token is $, then fail the parse.
      **
      ** As before, subsequent error messages are suppressed until
      ** three input tokens have been successfully shifted.
      */
      if( yypParser->yyerrcnt<=0 ){
        yy_syntax_error(yypParser,yymajor,yyminorunion);
      }
      yypParser->yyerrcnt = 3;
      yy_destructor((YYCODETYPE)yymajor,&yyminorunion);
      if( yyendofinput ){
        yy_parse_failed(yypParser);
      }
      yymajor = YYNOCODE;
#endif
    }
  }while( yymajor!=YYNOCODE && yypParser->yyidx>=0 );
  return;
}
