#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <stdlib.h>  /* NULL, strtod() */
#include <errno.h>  /* ERANGE */
#include <math.h>   /* HUGE_VAL */

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch) ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch) ((ch) >= '1' && (ch) <= '9')

typedef struct {
    const char* json;
}lept_context;

static void lept_parse_whitespace(lept_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int lept_parse_literal(lept_context* c, lept_value* v, const char* literal, lept_type type) {
    const char* iter = literal + 1;
    EXPECT(c, *literal);
    for(iter = literal + 1; *iter != '\0'; iter++) {
        if(*c->json != *iter)
            return LEPT_PARSE_INVALID_VALUE;
        c->json++;
    }
    v->type = type;
    return LEPT_PARSE_OK;
}

static int lept_parse_number(lept_context* c, lept_value* v) {
    char* end;
    int point_flag = 0, pre_exp = 0, first_ch = 1, begin_zero = 0;
    const char* temp = c->json;
    errno = 0;
    while(*temp != '\0') {
        if(begin_zero && *temp != '.' && *temp != 'E' && *temp != 'e')  return LEPT_PARSE_ROOT_NOT_SINGULAR;
        switch(ISDIGIT(*temp)) {
            /* 非数字0-9 */
            case 0: {
                switch (*temp) {
                    case '-' :  if(!first_ch && !pre_exp)    return LEPT_PARSE_INVALID_VALUE;
                                else if(pre_exp)    pre_exp = 0;
                                break;  /* 负号直接跳过 */
                    case '.' :  if(first_ch || point_flag || pre_exp || !ISDIGIT(*(temp+ 1)))   return LEPT_PARSE_INVALID_VALUE; /* 小数点只能出现一次，且之后必须有数字 */
                                point_flag = 1; 
                                break;
                    case '+' :  if(!pre_exp)    return LEPT_PARSE_INVALID_VALUE;    /* +号只能出现在E或e之后 */
                                pre_exp = 0; 
                                break;
                    case 'E' : case 'e' :   if(pre_exp) return LEPT_PARSE_INVALID_VALUE;
                                            pre_exp = 1;   
                                            break;
                    default :   return LEPT_PARSE_INVALID_VALUE;
                }
                break;
            } 
            /* 数字0-9 */
            default: {
                if(pre_exp) pre_exp = 0;
                switch(ISDIGIT1TO9(*temp)) {
                    case 0 : if(first_ch)  begin_zero = 1;  break;  /* 数字0若不是第一个字符直接跳过 */
                    default : if(begin_zero)    return LEPT_PARSE_INVALID_VALUE;    break;  /* 若是数字0开头且后面有非0数字，则判定非法，否则跳过 */
                }
                break;
            }
        }
        temp++;
        if(first_ch)
            first_ch = 0;
    }

    /* \TODO validate number */
    v->n = strtod(c->json, &end);
    /* strod()函数输入参数超出数学函数定义的范围时发生，errno 被设置为 ERANGE，返回值设置为0，因此下溢情况不必处理自动判定为0 */
    if(errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL)) return LEPT_PARSE_NUMBER_TOO_BIG;
    if (c->json == end) return LEPT_PARSE_INVALID_VALUE;
    c->json = end;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json) {
        case 't':  return lept_parse_literal(c, v, "true", LEPT_TRUE);
        case 'f':  return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case 'n':  return lept_parse_literal(c, v, "null", LEPT_NULL);
        default:   return lept_parse_number(c, v);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
    }
}

int lept_parse(lept_value* v, const char* json) {
    lept_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    v->type = LEPT_NULL;
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    return ret;
}

lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}

double lept_get_number(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->n;
}
