#include <string>

#include "AuthExprCalc.h"
#include <algorithm>
#include <stdexcept>

using namespace std;
using namespace tl::secure;

Token::Token() : type_(TokenType::Unknown), value_("")
{
}

Token::Token(TokenType type) : type_(type), value_("")
{
}

Token::Token(TokenType type, string value) : type_(type), value_(value)
{
}

Lexer::Lexer(const string &expr) : expr_(expr)
{
}

Token Lexer::next()
{
    while (expr_[pos_] == ' ')
    {
        ++pos_;
    }
    if (done())
    {
        return {TokenType::Unknown};
    }
    else if (expr_[pos_] == '(')
    {
        ++pos_;
        return {TokenType::LParen};
    }
    else if (expr_[pos_] == ')')
    {
        ++pos_;
        return {TokenType::RParen};
    }
    else if (expr_[pos_] == ',')
    {
        ++pos_;
        return {TokenType::Comma};
    }
    else if (expr_[pos_] == '\'' || expr_[pos_] == '"')
    {
        auto quote = expr_[pos_];
        string str = "";
        for (++pos_; !done() && expr_[pos_] != quote; ++pos_)
        {
            str += expr_[pos_];
        }
        if (!done())
        {
            ++pos_;
            return {TokenType::Str, str};
        }
    }
    else if (expr_[pos_] == 'h')
    {
        static const char *funcNameList[] = {"hasAuthority",
                                             "hasAnyAuthority",
                                             "hasRole",
                                             "hasAnyRole"};
        static const int funcNameLen[] = {12, 15, 7, 10};
        if (pos_ + 6 >= expr_.size())
        {
            throw runtime_error("Invalid expression string.");
        }
        int index = -1;
        switch (expr_[pos_ + 6])
        {
            case 'h':
                index = 0;
                break;
            case 'A':
                index = 1;
                break;
            case 'e':
                index = 2;
                break;
            case 'R':
                index = 3;
                break;
        }
        string_view func(expr_.data() + pos_, funcNameLen[index]);
        if (funcNameList[index] == func)
        {
            pos_ += funcNameLen[index];
            return {TokenType::Func, string(func)};
        }
    }
    else if (expr_[pos_] == 'a' && expr_[pos_ + 1] == 'n' &&
             expr_[pos_ + 2] == 'd')
    {
        pos_ += 3;
        return {TokenType::And};
    }
    else if (expr_[pos_] == '&' && expr_[pos_ + 1] == '&')
    {
        pos_ += 2;
        return {TokenType::And};
    }
    else if (expr_[pos_] == 'o' && expr_[pos_ + 1] == 'r')
    {
        pos_ += 2;
        return {TokenType::Or};
    }
    else if (expr_[pos_] == '|' && expr_[pos_ + 1] == '|')
    {
        pos_ += 2;
        return {TokenType::Or};
    }
    else if (expr_[pos_] == 'n' && expr_[pos_ + 1] == 'o' &&
             expr_[pos_ + 2] == 't')
    {
        pos_ += 3;
        return {TokenType::Not};
    }

    else if (expr_[pos_] == '!')
    {
        ++pos_;
        return {TokenType::Not};
    }
    throw runtime_error("Invalid expression string.");
}

bool Lexer::done()
{
    return pos_ == expr_.size();
}

AuthExprCalc::AuthExprCalc(const string &expr) : lexer_(expr)
{
    ahead_ = lexer_.next();
}

bool AuthExprCalc::calc(const vector<string> &authorities)
{
    auto result = expr(authorities);
    if (lexer_.done())
        return result;
    throw runtime_error("Invalid expression.");
}

bool AuthExprCalc::expr(const vector<string> &authorities)
{
    bool result = term(authorities);
    while (true)
    {
        if (ahead_.type_ == TokenType::Or)
        {
            match(TokenType::Or);
            result = term(authorities) || result;
            continue;
        }
        return result;
    }
}

bool AuthExprCalc::term(const vector<string> &authorities)
{
    bool result = factor(authorities);
    while (true)
    {
        if (ahead_.type_ == TokenType::And)
        {
            match(TokenType::And);
            result = factor(authorities) && result;
            continue;
        }
        return result;
    }
}

bool AuthExprCalc::factor(const vector<string> &authorities)
{
    bool flag = false;
    if (ahead_.type_ == TokenType::Not)
    {
        match(TokenType::Not);
        flag = true;
    }
    if (ahead_.type_ == TokenType::LParen)
    {
        match(TokenType::LParen);
        bool result = expr(authorities);
        match(TokenType::RParen);
        return flag ? !result : result;
    }
    auto result = boolExpr(authorities);
    return flag ? !result : result;
}

bool AuthExprCalc::boolExpr(const std::vector<std::string> &authorities)
{
    if (ahead_.value_ == "hasAuthority" || ahead_.value_ == "hasRole")
    {
        bool isAuth = ahead_.value_[3] == 'A';
        match(TokenType::Func);
        match(TokenType::LParen);
        auto arg = match(TokenType::Str);
        match(TokenType::RParen);
        return isAuth ? hasAuthority(arg, authorities)
                      : hasRole(arg, authorities);
    }
    else if (ahead_.value_ == "hasAnyAuthority" ||
             ahead_.value_ == "hasAnyRole")
    {
        bool isAuth = ahead_.value_[6] == 'A';
        match(TokenType::Func);
        match(TokenType::LParen);
        auto args = strList();
        match(TokenType::RParen);
        return isAuth ? hasAnyAuthority(args, authorities)
                      : hasAnyRole(args, authorities);
    }
    throw runtime_error("Invalid function name.");
}

vector<string> AuthExprCalc::strList()
{
    vector<string> strList = {};
    strList.emplace_back(match(TokenType::Str));
    while (true)
    {
        if (ahead_.type_ == TokenType::Comma)
        {
            match(TokenType::Comma);
            strList.emplace_back(match(TokenType::Str));
            continue;
        }
        return strList;
    }
}

string AuthExprCalc::match(TokenType type)
{
    if (ahead_.type_ == type)
    {
        auto value = ahead_.value_;
        ahead_ = lexer_.next();
        return value;
    }
    throw runtime_error("Invalid expression.");
}

bool AuthExprCalc::hasAuthority(const string &arg,
                                const vector<string> &authorities)
{
    return find(authorities.begin(), authorities.end(), arg) !=
           authorities.end();
}

bool AuthExprCalc::hasRole(const string &arg, const vector<string> &authorities)
{
    return hasAuthority("ROLE_" + arg, authorities);
}

bool AuthExprCalc::hasAnyAuthority(const vector<string> &args,
                                   const vector<string> &authorities)
{
    return any_of(authorities.begin(),
                  authorities.end(),
                  [&args](const string &authority) -> bool {
                      return find(args.begin(), args.end(), authority) !=
                             args.end();
                  });
}

bool AuthExprCalc::hasAnyRole(const vector<string> &args,
                              const vector<string> &authorities)
{
    vector<string> roles;
    roles.resize(args.size());
    transform(args.begin(),
              args.end(),
              roles.begin(),
              [](const string &arg) -> string { return "ROLE_" + arg; });
    return hasAnyAuthority(roles, authorities);
}
