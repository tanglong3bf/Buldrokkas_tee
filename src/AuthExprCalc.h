/**
 *  @file AuthExprCalc.h
 *  @brief Defines the lexer analyzer `Lexer` and the authority expression
 *  calculator `AuthExprCalc`.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @version 0.0.1
 */
#pragma once

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>

namespace tl::secure
{

enum class TokenType : u_int8_t
{
    And,
    Or,
    Not,
    LParen,
    RParen,
    Str,
    Comma,
    Func,
    Unknown
};

/**
 *  @class Token
 *  @brief The result of lexer analysis.
 *  @details While `type_` is `Str` or `Func`, `value_` means the string or the
 *  name of function. Otherwise `value_` is "".
 *
 *  @author tanglong3bf
 *  @date 2024.12.18
 *  @since 0.0.1
 *
 *  @see Lexer
 *  @see AuthExprCalc
 */
class Token
{
  public:
    /**
     *  {Unkown, ""}
     */
    Token();
    /**
     *  {type, ""}
     */
    Token(TokenType type);
    /**
     *  {type, value}
     */
    Token(TokenType type, std::string value);

  private:
    TokenType type_;
    std::string value_;
    friend class AuthExprCalc;
};

/**
 *  @class Lexer
 *  @brief Lexer analyzer for authority expression.
 *  @details This class analyzes the input string and produces a sequence of
 * `Token`s.
 *
 *  @author tanglong3bf
 *  @date 2024.12.18
 *  @since 0.0.1
 *
 *  @see Token
 *  @see AuthExprCalc
 */
class Lexer
{
  public:
    /**
     *  Constructor.
     *  @param expr Expression to be analyzed.
     */
    Lexer(const std::string &expr);

    /**
     *  Get next token.
     *  If there is no more token, `{Unkown, ""}` is returned.
     *  @return Token
     */
    Token next();

    /**
     *  Is all token parsed?
     *  @return `true` if all token are parsed, `false` otherwise.
     */
    bool done();

  private:
    std::string expr_;
    int pos_{0};
};

/**
 *  @class AuthExprCalc
 *  @brief Authority expression calculator.
 *  @details This class calculates the result of authority expression.
 *
 *  @author tanglong3bf
 *  @date 2024.12.18
 *  @since 0.0.1
 */
class AuthExprCalc
{
  public:
    /**
     *  Constructor.
     *  @param permExpr Authority expression to be calculated.
     */
    AuthExprCalc(const std::string &permExpr);

    /**
     *  Calculate the result of authority expression.
     *
     *  The authority expression grammar is as follows:
     *  @code
     *  <expr> ::= <term> {OR <term>}
     *  <term> ::= <factor> {AND <factor>}
     *  <factor> ::= [NOT] LPAREN <expr> RPAREN | [NOT] <bool_expr>
     *  <bool_expr> ::= FUNC LPAREN <str_list> RPAREN | FUNC LPAREN STR RPAREN
     *  <str_list> ::= STR {COMMA STR}
     *  @endcode
     *
     *  @param authorities A list of authorities.
     *  @return `true` if the authority expression is satisfied, `false`
     *  otherwise.
     *  @throws std::runtime_error If the input expression is invalid.
     */
    bool calc(const std::vector<std::string> &authorities);

  private:
    bool expr(const std::vector<std::string> &);

    bool term(const std::vector<std::string> &);

    bool factor(const std::vector<std::string> &);

    bool boolExpr(const std::vector<std::string> &);

    std::vector<std::string> strList();

    std::string match(TokenType);

    /**
     *  @{
     *  Functions to check the authority.
     */
    bool hasAuthority(const std::string &, const std::vector<std::string> &);

    bool hasRole(const std::string &, const std::vector<std::string> &);

    bool hasAnyAuthority(const std::vector<std::string> &,
                         const std::vector<std::string> &);

    bool hasAnyRole(const std::vector<std::string> &,
                    const std::vector<std::string> &);
    /** @} */

  private:
    Lexer lexer_;
    Token ahead_;
};
};  // namespace tl::secure
