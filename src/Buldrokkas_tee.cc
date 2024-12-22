/**
 *
 *  Buldrokkas_tee.cc
 *
 */

#include "AuthExprCalc.h"
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

const string &AuthenticationBase::classTypeName()
{
    static string classTypeName("tl::secure::AuthenticationBase");
    return classTypeName;
}

map<string, function<UserServiceBase *(void)>> UserServiceBase::map = {};
map<string, function<PasswordEncoderBase *(void)>> PasswordEncoderBase::map =
    {};
map<string, function<AuthenticationBase *(void)>> AuthenticationBase::map = {};

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
 *  @version 0.0.1
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
 *  @version 0.0.1
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
 *  @version 0.0.1
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

/**
 *  @class DefaultAuthentication
 *  @brief Check username and password with the user service.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @version 0.0.1
 */
class DefaultAuthentication : public Authentication<DefaultAuthentication>
{
  public:
    DefaultAuthentication()
        : userService_(DrClassMap::getSingleInstance<UserServiceBase>()),
          passwordEncoder_(DrClassMap::getSingleInstance<PasswordEncoderBase>())
    {
    }

  public:
    User authenticate(const string &username,
                      const string &password) const override
    {
        try
        {
            auto user = userService_->loadUserByUsername(username);
            if (passwordEncoder_->matches(password, user.password()))
            {
                return user;
            }
        }
        catch (const exception &e)
        {
            LOG_ERROR << e.what();
        }
        throw runtime_error("Authentication failed");
    }

  private:
    shared_ptr<UserServiceBase> userService_;
    shared_ptr<PasswordEncoderBase> passwordEncoder_;
};

/**
 *  @class DefaultLoginCheckFilter
 *  @brief Default login check filter.
 *
 *  TODO: Specify a custom login check filter through the configuration item
 * `login_check_filter`.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @version 0.0.1
 */
class DefaultLoginCheckFilter
    : public drogon::HttpFilter<DefaultLoginCheckFilter>
{
  public:
    DefaultLoginCheckFilter()
        : authentication_(DrClassMap::getSingleInstance<AuthenticationBase>())
    {
    }

    /**
     *  @brief Utilize Basic authenticaion to check whether the user is logged
     *  in.
     *  If authentication is successful, the user information will be stored
     *  in the request attributes.
     *  If authentication fails, a 401 Unauthorized response will be returned.
     */
    void doFilter(const HttpRequestPtr &req,
                  FilterCallback &&fcb,
                  FilterChainCallback &&fccb)
    {
        auto notLoginHandler = [fcb]() {
            auto resp =
                HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE);
            resp->addHeader("WWW-Authenticate", "Basic realm=\"Realm\"");
            fcb(resp);
        };
        if (req->headers().count("authorization") == 0)
        {
            notLoginHandler();
            return;
        }
        auto authorization = req->headers().at("authorization");
        if (authorization.find("Basic ") != 0)
        {
            notLoginHandler();
            return;
        }
        auto token = authorization.substr(6);
        auto usernamePasswordStr = base64Decode(token);
        auto usernamePasswordVec = splitString(usernamePasswordStr, ":");
        try
        {
            auto user = authentication_->authenticate(usernamePasswordVec[0],
                                                      usernamePasswordVec[1]);
            req->attributes()->insert("user", user);
            req->attributes()->insert("authorities", user.authorities());
            fccb();
            return;
        }
        catch (const exception &e)
        {
            LOG_ERROR << e.what();
        }
        notLoginHandler();
    }

  private:
    shared_ptr<AuthenticationBase> authentication_;
};

/**
 *  @class AuthExprCalcItem
 *  @brief Authority Expression Calculator Item
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @version 0.0.1
 */
struct AuthExprCalcItem
{
    /**
     *  @brief Different request methods of the same path are calculated
     *  separately, and array subscripts are distinguished by HttpMethod.
     */
    shared_ptr<AuthExprCalc> calculators[drogon::Invalid]{nullptr};
};

/**
 *  @class PermissionCheckFilter
 *  @brief Permission check filter.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @version 0.0.1
 */
class PermissionCheckFilter : public drogon::HttpFilter<PermissionCheckFilter>
{
  public:
    PermissionCheckFilter()
    {
    }

    void doFilter(const HttpRequestPtr &req,
                  FilterCallback &&fcb,
                  FilterChainCallback &&fccb)
    {
        if (!req->attributes()->find("authorities"))
        {
            fcb(HttpResponse::newHttpResponse(k401Unauthorized, CT_NONE));
            return;
        }
        vector<string> authorities =
            req->attributes()->get<vector<string>>("authorities");
        auto path = req->path();
        auto method = req->method();
        auto it = authExprCalcs_.find(path);
        if (it == authExprCalcs_.end())
        {
            fccb();
        }
        else
        {
            auto &item = it->second;
            auto &calculator = item.calculators[method];
            if (!calculator || calculator->calc(authorities))
            {
                fccb();
            }
            else
            {
                fcb(HttpResponse::newHttpResponse(k403Forbidden, CT_NONE));
            }
        }
    }

    void setAuthExprCalcs(
        const unordered_map<string, AuthExprCalcItem> &authExprCalcs)
    {
        authExprCalcs_ = authExprCalcs;
    }

  private:
    unordered_map<string, AuthExprCalcItem> authExprCalcs_;
};
};  // namespace tl::secure

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
    auto authenticationName =
        config.get("authentication", "tl::secure::Authentication").asString();
    DrClassMap::registerClass("tl::secure::AuthenticationBase",
                              AuthenticationBase::map.at(authenticationName));

    passwordEncoder_ = DrClassMap::getSingleInstance<PasswordEncoderBase>();
    userService_ = DrClassMap::getSingleInstance<UserServiceBase>();

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
    unordered_map<string, AuthExprCalcItem> permExprCalcs;
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
                        permExprCalcs[path].calculators[method] = calculator;
                    }
                }
                else
                {
                    for (int i = 0; i < Invalid; i++)
                    {
                        permExprCalcs[path].calculators[i] = calculator;
                    }
                }
            }
        }
    }

    /// Get the filters.
    vector<string> filterNames;
    filterNames.emplace_back("tl::secure::DefaultLoginCheckFilter");
    filterNames.emplace_back("tl::secure::PermissionCheckFilter");

    for (const auto &filterName : filterNames)
    {
        auto filterPtr = dynamic_pointer_cast<HttpFilterBase>(
            DrClassMap::getSingleInstance(filterName));
        if (!filterPtr)
        {
            LOG_ERROR << "Filter " << filterName << " not found!";
            continue;
        }
        else if (filterName == "tl::secure::PermissionCheckFilter")
        {
            dynamic_pointer_cast<PermissionCheckFilter>(filterPtr)
                ->setAuthExprCalcs(permExprCalcs);
        }
        filters_.push_back(filterPtr);
    }

    /// Register the filters to the app
    weak_ptr<Buldrokkas_tee> weakPtr = shared_from_this();
    app().registerPreRoutingAdvice([weakPtr](const HttpRequestPtr &req,
                                             AdviceCallback &&acb,
                                             AdviceChainCallback &&accb) {
        auto thisPtr = weakPtr.lock();
        if (!thisPtr)
        {
            accb();
            return;
        }

        middlewares_function::doFilters(
            thisPtr->filters_,
            static_pointer_cast<HttpRequestImpl>(req),
            [acb = std::move(acb), accb = std::move(accb)](
                const HttpResponsePtr &resp) { resp ? acb(resp) : accb(); });
    });
}

void Buldrokkas_tee::shutdown()
{
    /// Shutdown the plugin
}
