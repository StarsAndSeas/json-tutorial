#ifdef _WINDOWS
#define _CRTDBG_MAP_ALLOC
#include <crtdbg.h>
#endif
#include "leptjson.h"
#include <assert.h>  /* assert() */
#include <errno.h>   /* errno, ERANGE */
#include <math.h>    /* HUGE_VAL */
#include <stdlib.h>  /* NULL, malloc(), realloc(), free(), strtod() */
#include <string.h>  /* memcpy() */

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#define EXPECT(c, ch)       do { assert(*c->json == (ch)); c->json++; } while(0)
#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')
#define PUTC(c, ch)         do { *(char*)lept_context_push(c, sizeof(char)) = (ch); } while(0)

typedef struct {
    const char* json;
    char* stack;
    size_t size, top;
}lept_context;

static void* lept_context_push(lept_context* c, size_t size) {
    void* ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0)
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size >> 1;  /* c->size * 1.5 */
        c->stack = (char*)realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void* lept_context_pop(lept_context* c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

static void lept_parse_whitespace(lept_context* c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    c->json = p;
}

static int lept_parse_literal(lept_context* c, lept_value* v, const char* literal, lept_type type) {
    size_t i;
    EXPECT(c, literal[0]);
    for (i = 0; literal[i + 1]; i++)
        if (c->json[i] != literal[i + 1])
            return LEPT_PARSE_INVALID_VALUE;
    c->json += i;
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
    v->u.n = strtod(c->json, &end);
    /* strod()函数输入参数超出数学函数定义的范围时发生，errno 被设置为 ERANGE，返回值设置为0，因此下溢情况不必处理自动判定为0 */
    if(errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n== -HUGE_VAL)) return LEPT_PARSE_NUMBER_TOO_BIG;
    if (c->json == end) return LEPT_PARSE_INVALID_VALUE;
    c->json = end;
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static const char* lept_parse_hex4(const char* p, unsigned* u) {
    /* \TODO */
    int i;
    *u = 0;
    for(i = 0; i < 4; i++){
        *u <<= 4;
        if(*p <= '9' && *p >= '0')  *u += *p++ - '0';
        else if(*p >= 'a' && *p <= 'f') *u += *p++ - ('a' - 10);
        else if(*p >= 'A' && *p <= 'F') *u += *p++ - ('A' - 10);
        else    return NULL;
    }
    return p;
}

static void lept_encode_utf8(lept_context* c, unsigned u) {
    /* 输入码点必须在0x0000 ~ 0x10FFFFF范围内 */
    assert(u <= 0x10FFFFF);
    if (u <= 0x007F) PUTC(c, u & 0x7F);
    else if (u >= 0x0080 && u <= 0x07FF){ PUTC(c, 0xC0 | ((u >> 6) & 0x1F)); PUTC(c, 0x80 | (u & 0x3F));}
    else if (u >= 0x0800 && u <= 0xFFFF){ PUTC(c, 0xE0 | ((u >> 12) & 0x0F)); PUTC(c, 0x80 | ((u >> 6) & 0x3F)); PUTC(c, 0x80 | (u & 0x3F)); }
    else if (u >= 0x10000 && u <= 0x10FFFF){ PUTC(c, 0xF0 | ((u >> 18) & 0x07)); PUTC(c, 0x80 | ((u >> 12) & 0x3F)); PUTC(c, 0x80 | ((u >> 6) & 0x3F)); PUTC(c, 0x80 | (u & 0x3F)); }
}

#define STRING_ERROR(ret) do { c->top = head; return ret; } while(0)

static int lept_parse_string(lept_context* c, lept_value* v) {
    size_t head = c->top, len;
    unsigned u;
    const char* p;
    EXPECT(c, '\"');
    p = c->json;
    for (;;) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                len = c->top - head;
                lept_set_string(v, (const char*)lept_context_pop(c, len), len);
                c->json = p;
                return LEPT_PARSE_OK;
            case '\\':
                switch (*p++) {
                    case '\"': PUTC(c, '\"'); break;
                    case '\\': PUTC(c, '\\'); break;
                    case '/':  PUTC(c, '/' ); break;
                    case 'b':  PUTC(c, '\b'); break;
                    case 'f':  PUTC(c, '\f'); break;
                    case 'n':  PUTC(c, '\n'); break;
                    case 'r':  PUTC(c, '\r'); break;
                    case 't':  PUTC(c, '\t'); break;
                    case 'u':
                        if (!(p = lept_parse_hex4(p, &u)))
                            STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        if (u >= 0xD800 && u <= 0xDBFF) {
                            unsigned t;
                            /* 下一个仍是\u转义字符 */
                            if (*p++ == '\\' && *p++ == 'u') {
                                if (!(p = lept_parse_hex4(p, &t)))
                                    STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                                if(t >= 0xDC00 && t <= 0xDFFF)  u = 0x10000 + (u - 0xD800) * 0x400 + (t - 0xDC00);
                                else    STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            }
                            else STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                        }
                        /* \TODO surrogate handling */
                        lept_encode_utf8(c, u);
                        break;
                    default:
                        STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            case '\0':
                STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
            default:
                if ((unsigned char)ch < 0x20)
                    STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
                PUTC(c, ch);
        }
    }
}

static int lept_parse_value(lept_context* c, lept_value* v) {
    switch (*c->json) {
        case 't':  return lept_parse_literal(c, v, "true", LEPT_TRUE);
        case 'f':  return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case 'n':  return lept_parse_literal(c, v, "null", LEPT_NULL);
        default:   return lept_parse_number(c, v);
        case '"':  return lept_parse_string(c, v);
        case '\0': return LEPT_PARSE_EXPECT_VALUE;
    }
}

int lept_parse(lept_value* v, const char* json) {
    lept_context c;
    int ret;
    assert(v != NULL);
    c.json = json;
    c.stack = NULL;
    c.size = c.top = 0;
    lept_init(v);
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json != '\0') {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

void lept_free(lept_value* v) {
    assert(v != NULL);
    if (v->type == LEPT_STRING)
        free(v->u.s.s);
    v->type = LEPT_NULL;
}

lept_type lept_get_type(const lept_value* v) {
    assert(v != NULL);
    return v->type;
}

int lept_get_boolean(const lept_value* v) {
    assert(v != NULL && (v->type == LEPT_TRUE || v->type == LEPT_FALSE));
    return v->type == LEPT_TRUE;
}

void lept_set_boolean(lept_value* v, int b) {
    lept_free(v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

double lept_get_number(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.n;
}

void lept_set_number(lept_value* v, double n) {
    lept_free(v);
    v->u.n = n;
    v->type = LEPT_NUMBER;
}

const char* lept_get_string(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}

size_t lept_get_string_length(const lept_value* v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.len;
}

void lept_set_string(lept_value* v, const char* s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->u.s.s = (char*)malloc(len + 1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = LEPT_STRING;
}
