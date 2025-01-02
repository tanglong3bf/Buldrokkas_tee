/**
 *
 *  Buldrokkas_tee.cc
 *
 */

#include "Buldrokkas_tee.h"
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>

using namespace ::std;
using namespace ::drogon;
using namespace ::drogon::utils;
using namespace ::tl::secure;

namespace drogon
{
class HttpRequestImpl : public HttpRequest
{
};

namespace middlewares_function
{
using HttpRequestImplPtr = shared_ptr<HttpRequestImpl>;
void doFilters(const vector<shared_ptr<HttpFilterBase>> &filters,
               const HttpRequestImplPtr &req,
               function<void(const HttpResponsePtr &)> &&callback);
}  // namespace middlewares_function
}  // namespace drogon

const string &UserServiceBase::classTypeName()
{
    static string classTypeName("tl::secure::UserServiceBase");
    return classTypeName;
}

const string &PasswordEncoderBase::classTypeName()
{
    static string classTypeName("tl::secure::PasswordEncoderBase");
    return classTypeName;
}

map<string, function<UserServiceBase *(void)>> UserServiceBase::map = {};
map<string, function<PasswordEncoderBase *(void)>> PasswordEncoderBase::map =
    {};

User::User(const string &username, const string &password)
    : username_(username), password_(password)
{
}

User &User::addRole(const string &role)
{
    authorities_.emplace_back("ROLE_" + role);
    return *this;
}

User &User::addRoles(const vector<string> &roles)
{
    for (auto role : roles)
    {
        authorities_.emplace_back("ROLE_" + role);
    }
    return *this;
}

User &User::addAuthority(const string &authority)
{
    authorities_.emplace_back(authority);
    return *this;
}

User &User::addAuthorities(const vector<string> &authorities)
{
    for (auto authority : authorities)
    {
        authorities_.emplace_back(authority);
    }
    return *this;
}

const string &User::username() const
{
    return username_;
}

const string &User::password() const
{
    return password_;
}

const vector<string> User::authorities() const
{
    return authorities_;
}

/**
 *  @namespace tl::secure
 */
namespace tl::secure
{
/**
 *  @class InMemoryUserService
 *  @brief All user data is stored in memory.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @since 0.0.1
 */
class InMemoryUserService : public UserService<InMemoryUserService>
{
  public:
    InMemoryUserService()
    {
    }

  public:
    User loadUserByUsername(const string &username) const override
    {
        if (users_.find(username) == users_.end())
        {
            LOG_ERROR << "User not found, username: " << username;
            throw runtime_error("User not found");
        }
        return users_.at(username);
    }

    /**
     *  Add a user to the user service.
     *  @param user The user to be added.
     */
    void addUser(const User &user)
    {
        users_.emplace(user.username(), user);
    }

  private:
    unordered_map<string, User> users_;
};

/**
 *  @class NonePasswordEncoder
 *  @brief Don't encode the password.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @since 0.0.1
 */
class NonePasswordEncoder : public PasswordEncoder<NonePasswordEncoder>
{
  public:
    NonePasswordEncoder()
    {
    }

  public:
    string encode(const string &raw) const override
    {
        return raw;
    }

    bool matches(const string &raw, const string &encoded) const override
    {
        return raw == encoded;
    }
};

/**
 *  @class Md5PasswordEncoder
 *  @brief Encode the password with MD5.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @since 0.0.1
 */
class Md5PasswordEncoder : public PasswordEncoder<Md5PasswordEncoder>
{
  public:
    Md5PasswordEncoder()
    {
    }

  public:
    string encode(const string &raw) const override
    {
        return getMd5(raw);
    }

    bool matches(const string &raw, const string &encoded) const override
    {
        return getMd5(raw) == encoded;
    }
};
};  // namespace tl::secure

Authentication::Authentication()
    : userService_(drogon::DrClassMap::getSingleInstance<UserServiceBase>()),
      passwordEncoder_(
          drogon::DrClassMap::getSingleInstance<PasswordEncoderBase>())
{
}

optional<User> Authentication::authenticate(const std::string &username,
                                            const std::string &password) const
{
    try
    {
        auto user = userService_->loadUserByUsername(username);
        if (passwordEncoder_->matches(password, user.password()))
        {
            return user;
        }
    }
    catch (const std::exception &e)
    {
        LOG_ERROR << e.what();
    }
    return nullopt;
}

void Buldrokkas_tee::registerLoginCheckHandler(
    function<optional<User>(const HttpRequestPtr &)> handler)
{
    loginCheckHandler_ = handler;
}

HttpMethod fromStringToHttpMethod(const string &methodStr)
{
    if (methodStr == "GET" || methodStr == "get" || methodStr == "Get")
    {
        return HttpMethod::Get;
    }
    else if (methodStr == "POST" || methodStr == "post" || methodStr == "Post")
    {
        return HttpMethod::Post;
    }
    else if (methodStr == "PUT" || methodStr == "put" || methodStr == "Put")
    {
        return HttpMethod::Put;
    }
    else if (methodStr == "DELETE" || methodStr == "delete" ||
             methodStr == "Delete")
    {
        return HttpMethod::Delete;
    }
    else if (methodStr == "HEAD" || methodStr == "head" || methodStr == "Head")
    {
        return HttpMethod::Head;
    }
    else if (methodStr == "PATCH" || methodStr == "patch" ||
             methodStr == "Patch")
    {
        return HttpMethod::Patch;
    }
    else if (methodStr == "OPTIONS" || methodStr == "options" ||
             methodStr == "Options")
    {
        return HttpMethod::Options;
    }
    else
    {
        return HttpMethod::Invalid;
    }
}

void Buldrokkas_tee::initAndStart(const Json::Value &config)
{
    /// Register various types to the class map.
    auto passwordEncoderName =
        config.get("password_encoder", "tl::secure::NonePasswordEncoder")
            .asString();
    DrClassMap::registerClass("tl::secure::PasswordEncoderBase",
                              PasswordEncoderBase::map.at(passwordEncoderName));
    auto userServiceName =
        config.get("user_service", "tl::secure::InMemoryUserService")
            .asString();
    DrClassMap::registerClass("tl::secure::UserServiceBase",
                              UserServiceBase::map.at(userServiceName));

    passwordEncoder_ = DrClassMap::getSingleInstance<PasswordEncoderBase>();
    userService_ = DrClassMap::getSingleInstance<UserServiceBase>();
    authentication_ = make_shared<Authentication>();

    /// If it is memory user service, initialize the user list.
    if (userServiceName == "tl::secure::InMemoryUserService")
    {
        auto inMemoryUserService =
            dynamic_pointer_cast<InMemoryUserService>(userService_);
        if (!config.isMember("user_list") || !config["user_list"].isArray() ||
            config["user_list"].size() == 0)
        {
            LOG_INFO << "No user found in config, add default admin user";
            LOG_INFO << "Username: admin123, Password: 123456";
            inMemoryUserService->addUser(
                User("admin123", passwordEncoder_->encode("123456"))
                    .addRole("admin"));
        }
        else
        {
            for (const auto &user : config["user_list"])
            {
                if (!user.isObject() || !user.isMember("username") ||
                    !user["username"].isString() ||
                    !user.isMember("password") || !user["password"].isString())
                {
                    continue;
                }
                User u(user["username"].asString(),
                       passwordEncoder_->encode(user["password"].asString()));
                if (user.isMember("roles") && user["roles"].isArray())
                {
                    vector<string> roles;
                    for (const auto &role : user["roles"])
                    {
                        if (role.isString())
                        {
                            roles.emplace_back(role.asString());
                        }
                    }
                    u.addRoles(roles);
                }
                if (user.isMember("authorities") &&
                    user["authorities"].isArray())
                {
                    vector<string> authorities;
                    for (const auto &authority : user["authorities"])
                    {
                        if (authority.isString())
                        {
                            authorities.emplace_back(authority.asString());
                        }
                    }
                    u.addAuthorities(authorities);
                }
                inMemoryUserService->addUser(u);
            }
        }
    }

    /// Set path authorities.
    unordered_map<string, AuthExprCalcItem> authExprCalcs;
    if (config.isMember("path_authorities") &&
        config["path_authorities"].isArray())
    {

        for (const auto &authority : config["path_authorities"])
        {
            if (!authority.isObject())
                continue;
            if (!authority.isMember("path") || !authority["path"].isString() ||
                !authority.isMember("auth_expression") ||
                !authority["auth_expression"].isString())
            {
                LOG_ERROR << "缺少必备参数";
                continue;
            }
            string path = authority["path"].asString();
            string authExpr = authority["auth_expression"].asString();
            auto calculator = make_shared<AuthExprCalc>(authExpr);
            if (authority.isMember("methods"))
            {
                vector<HttpMethod> methods;
                if (authority["methods"].isArray() &&
                    authority["methods"].size() > 0)
                {
                    for (const auto &method : authority["methods"])
                    {
                        method.isString()
                            ? methods.push_back(
                                  fromStringToHttpMethod(method.asString()))
                            : void(0);
                    }
                }
                else if (authority["methods"].isString())
                {
                    methods.push_back(fromStringToHttpMethod(
                        authority["methods"].asString()));
                }
                if (methods.size() > 0)
                {
                    for (const auto &method : methods)
                    {
                        authExprCalcs[path].calculators[method] = calculator;
                    }
                }
                else
                {
                    for (int i = 0; i < Invalid; i++)
                    {
                        authExprCalcs[path].calculators[i] = calculator;
                    }
                }
            }
        }
    }

    /// Get the exempt paths.
    if (config.isMember("exempt"))
    {
        auto exempt = config["exempt"];
        if (exempt.isArray())
        {
            std::string regexStr;
            for (auto const &ex : exempt)
            {
                if (ex.isString())
                {
                    regexStr.append("(?:").append(ex.asString()).append(")|");
                }
                else
                {
                    LOG_ERROR << "exempt must be a string array!";
                }
            }
            if (!regexStr.empty())
            {
                regexStr.pop_back();
                exemptRegex_ = std::regex(regexStr);
                regexFlag_ = true;
            }
        }
        else if (exempt.isString())
        {
            exemptRegex_ = std::regex(exempt.asString());
            regexFlag_ = true;
        }
        else
        {
            LOG_ERROR << "exempt must be a string or string array!";
        }
    }

    /// Register a pre-routing advice to check the authentication.
    app().registerPreRoutingAdvice([this](const HttpRequestPtr &req,
                                          AdviceCallback &&acb,
                                          AdviceChainCallback &&accb) {
        if (!loginCheckHandler_)
        {
            loginCheckHandler_ =
                [this](const HttpRequestPtr &req) -> optional<User> {
                if (req->headers().count("authorization") == 0)
                {
                    return nullopt;
                }
                auto authorization = req->headers().at("authorization");
                if (authorization.find("Basic ") != 0)
                {
                    return nullopt;
                }
                auto token = authorization.substr(6);
                auto usernamePasswordStr = base64Decode(token);
                auto usernamePasswordVec =
                    splitString(usernamePasswordStr, ":");
                return authentication_->authenticate(usernamePasswordVec[0],
                                                     usernamePasswordVec[1]);
            };
        }
        auto user = loginCheckHandler_(req);
        if (!user)
        {
            auto resp =
                HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE);
            resp->addHeader("WWW-Authenticate", "Basic realm=\"Realm\"");
            acb(resp);
            return;
        }
        req->attributes()->insert("user", *user);
        req->attributes()->insert("authorities", user->authorities());
        accb();
    });

    /// Register a pre-routing advice to check the path authorities.
    app().registerPreRoutingAdvice([this](const HttpRequestPtr &req,
                                          AdviceCallback &&acb,
                                          AdviceChainCallback &&accb) {
        if (!req->attributes()->find("authorities"))
        {
            acb(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
            return;
        }
        vector<string> authorities =
            req->attributes()->get<vector<string>>("authorities");
        auto path = req->path();
        auto method = req->method();
        for (const auto &item : authExprCalcs_)
        {
            std::regex regex(item.first);
            if (std::regex_match(req->path(), regex))
            {
                auto &it = item.second;
                auto &calculator = it.calculators[method];
                if (!calculator || calculator->calc(authorities))
                {
                    accb();
                }
                else
                {
                    acb(HttpResponse::newHttpResponse(k403Forbidden, CT_NONE));
                }
            }
        }
        accb();
    });
}

void Buldrokkas_tee::shutdown()
{
    /// Shutdown the plugin
}
