/**
 *  @mainpage Buldrokkas_tee
 *  @section Project Introduction
 *  Buldrokkas_tee is a plug-in that provides authorization management for the
 *  open source project Drogon.
 *  Support role-based and authority expression based authority management.
 *  @section Default Configuration
 *  @code
    plugins:
      - name: tl::secure::Buldrokkas_tee
        config:
          # The service class to obtain user information. Default value:
          # "tl::secure::InMemoryUserService"
          # You can inherit `tl::secure::UserService` implements the
          # custom user service, just change this item to your custom class
          # name.
          user_service: tl::secure::InMemoryUserService
          # Only valid when user_service is "tl::secure::InMemoryUserService" If
          # user_list is not set, the default username is "admin123", the
          # default password is "123456", and the default authorities is [].
          user_list:
            - username: admin123
              password: "123456"
              roles:
                - admin
                - user
              authorities: []
          # Password encoder. Default value: "tl::secure::NonePasswordEncoder"
          # Optional values:
          # "tl::secure::NonePasswordEncoder"
          # "tl::secure::Md5PasswordEncoder"
          # You can inherit `tl::secure::PasswordEncoder` implements the custom
          # password encoder, just change this item to your custom class name.
          password_encoder: tl::secure::NonePasswordEncoder
          # Authentication. Default value: "tl::secure::DefaultAuthentication"
          # You can inherit `tl::secure::Authentication` implements the custom
          # authentication, just change this item to your custom class name.
          authentication: tl::secure::DefaultAuthentication
          # TODO: NOT SUPPORT YET
          white_list: []
          # Path authority configuration, "path" and "auth_expression" are
          # required, "methods" is optional If "methods" is not set, all methods
          # are subject to authentication control by default. Default value: []
          path_authorities:
            - path: "/test"
              methods: "GET"
              auth_expression: "hasRole('admin') or hasAuthority('test')"
 *  @endcode
 */
/**
 *  @file Buldrokkas_tee.h
 *  @brief Definition of Buldrokkas_tee plug-in.
 *  @details The built-in User class, UserService class, PasswordEncoder class,
 *  Authentication class, and Buldrokkas_tee class are defined.
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @version 0.0.2
 */
#pragma once

#include <drogon/HttpTypes.h>
#include <drogon/plugins/Plugin.h>
#include <drogon/utils/Utilities.h>
#include <drogon/HttpFilter.h>

namespace tl::secure
{

/**
 *  @class User
 *
 *  @details Used internally by the plugin to represent user information,
 * including username, password, role, and permissions.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @since 0.0.1
 */
class User
{
  public:
    User() = default;

    User(const std::string &username, const std::string &password);

    /**
     *  Add a role to the user.
     *
     *  A fixed prefix 'ROLE_' is added to the role name to distinguish between
     *  normal authority and role authority.
     *  @param role The name of new role.
     */
    User &addRole(const std::string &role);

    /**
     *  Add multiple roles to the user.
     *
     *  A fixed prefix 'ROLE_' is added to the role name to distinguish between
     *  normal authority and role authority.
     *  @param roles The list of new roles.
     */
    User &addRoles(const std::vector<std::string> &roles);

    /**
     *  Add authority to the user.
     *
     *  @param authority The name of new authority.
     */
    User &addAuthority(const std::string &authority);

    /**
     *  Add multiple authorities to the user.
     *
     *  @param authority The list of new authorities.
     */
    User &addAuthorities(const std::vector<std::string> &authorities);

    const std::string &username() const;

    const std::string &password() const;

    const std::vector<std::string> authorities() const;

  private:
    std::string username_;
    std::string password_;
    std::vector<std::string> authorities_;
};

/**
 *  @class UserServiceBase
 *
 *  @brief The base of user service.
 *  @details Defines the user service interface.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @version 0.0.1
 */
class UserServiceBase : public virtual drogon::DrObjectBase
{
  public:
    /**
     *  Load user by username.
     *
     *  @param username
     *  @return User info.
     *  @throws std::runtime_error User not found.
     */
    virtual User loadUserByUsername(
        const std::string &username) const = 0;

    /**
     *  Return current class type name.
     *
     *  @return Current class type name("tl::secure::UserServiceBase")
     */
    static const std::string &classTypeName();
    /**
     *  Stores multiple lambda expressions that can create instances of
     *  `UserService` subclasses
     *
     *  @note `UserService` will register real types to this map.
     */
    static std::map<std::string, std::function<UserServiceBase *(void)>> map;
};

/**
 *  @class UserService
 *
 *  @brief User service class.
 *  @details Inherits from `UserServiceBase`. If you want to implement a custom
 *  user service, you can inherit this class.
 *
 *  Example code:
 *  @code
    class MyUserService : public UserService<MyUserService>
    {
      public:
        MyUserService()
        {
        }
      public:
        const User &loadUserByUsername(const std::string &) const override
        {
            // Implementing custom user loading logic
        }
    };
 *  @endcode
 *
 *  @tparam T The type of the implementation class.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @version 0.0.1
 *
 *  @see UserServiceBase
 *  @see InMemoryUserService
 */
template <typename T>
class UserService : public UserServiceBase, public drogon::DrObject<T>
{
  public:
    /**
     *  Do not automatically create an instance.
     *  @see drogon::DrObject<T>
     */
    static constexpr bool isAutoCreation{false};

  private:
    class Emm
    {
      public:
        Emm()
        {
            setLambda();
        }

        const std::string &className() const
        {
            static std::string className =
                drogon::DrClassMap::demangle(typeid(T).name());
            return className;
        }

        void setLambda()
        {
            map[className()] = [] { return new T; };
        }
    };

    static Emm emm;

    virtual void *touch()
    {
        return &emm;
    }
};

template <typename T>
typename UserService<T>::Emm UserService<T>::emm;

/**
 *  @class PasswordEncoderBase
 *
 *  @brief The base of password encoder.
 *  @details Defines the password encoder interface.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @since 0.0.1
 */
class PasswordEncoderBase : public virtual drogon::DrObjectBase
{
  public:
    /**
     *  Encode password.
     *  @param password
     *  @return Encoded password.
     */
    virtual std::string encode(const std::string &password) const = 0;
    /**
     *  Verify password.
     *  @param raw Raw password.
     *  @param encoded Encoded password.
     *  @return True if the raw password matches the encoded password, false
     *  otherwise.
     */
    virtual bool matches(const std::string &raw,
                         const std::string &encoded) const = 0;

    /**
     *  Return current class type name.
     *
     *  @return Current class type name("tl::secure::PasswordEncoderBase")
     */
    static const std::string &classTypeName();
    /**
     *  Stores multiple lambda expressions that can create instances of
     *  `PasswordEncoder` subclasses
     *
     *  @note `PasswordEncoder` will register real types to this map.
     */
    static std::map<std::string, std::function<PasswordEncoderBase *(void)>>
        map;
};

/**
 *  @class PasswordEncoder
 *
 *  @brief Password encoder class.
 *  @details Inherits from `PasswordEncoderBase`. If you want to implement a
 *  custom password encoder, you can inherit this class.
 *
 *  Example code:
 *  @code
    class MyPasswordEncoder : public PasswordEncoder<MyPasswordEncoder>
    {
      public:
        MyPasswordEncoder()
        {
        }
      public:
        std::string encode(const std::string &password) const override
        {
            // Implementing custom password encoding logic
        }
        bool matched(const std::string &raw,
                     const std::string &encoded) const override
        {
            // Implementing custom password verification logic
        }
    };
 *  @endcode
 *
 *  @tparam T The type of the implementation class.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @version 0.0.1
 *
 *  @see PasswordEncoderBase
 *  @see NonePasswordEncoder
 *  @see Md5PasswordEncoder
 */
template <typename T>
class PasswordEncoder : public PasswordEncoderBase, public drogon::DrObject<T>
{
  public:
    /**
     *  Do not automatically create an instance.
     *  @see drogon::DrObject<T>
     */
    static constexpr bool isAutoCreation{false};

  private:
    class Emm
    {
      public:
        Emm()
        {
            setLambda();
        }

        const std::string &className() const
        {
            static std::string className =
                drogon::DrClassMap::demangle(typeid(T).name());
            return className;
        }

        void setLambda()
        {
            map[className()] = [] { return new T; };
        }
    };

    static Emm emm;

    virtual void *touch()
    {
        return &emm;
    }
};

template <typename T>
typename PasswordEncoder<T>::Emm PasswordEncoder<T>::emm;

/**
 *  @class AuthenticationBase
 *
 *  @brief The base of authentication.
 *  @details Defines the authentication interface.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @since 0.0.1
 */
class AuthenticationBase : public virtual drogon::DrObjectBase
{
  public:
    /**
     *  Authenticate user.
     *
     *  @param username
     *  @param password
     *  @return User info if authentication succeeds.
     *  @throws std::runtime_error Authentication failed.
     */
    virtual User authenticate(const std::string &username,
                              const std::string &password) const = 0;

    /**
     *  Return current class type name.
     *
     *  @return Current class type name("tl::secure::AuthenticationBase")
     */
    static const std::string &classTypeName();
    /**
     *  Stores multiple lambda expressions that can create instances of
     * `Authentication` subclasses
     *
     *
     *  @note `Authentication` will register real types to this map.
     */
    static std::map<std::string, std::function<AuthenticationBase *(void)>> map;
};

/**
 *  @class Authentication
 *
 *  @brief Authentication class.
 *  @details Inherits from `AuthenticationBase`. If you want to implement a
 *  custom authentication, you can inherit this class.
 *
 *  Example code:
 *  @code
    class MyAuthentication : public Authentication<MyAuthentication>
    {
      public:
        MyAuthentication()
        {
        }
      public:
        User authenticate(const std::string &username
                          const std::string &password) const override
        {
            // Implementing custom authentication logic
        }
    };
 *  @endcode
 *
 *  @tparam T The type of the implementation class.
 *
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @version 0.0.1
 *
 *  @see AuthenticationBase
 *  @see DefaultAuthentication
 */
template <typename T>
class Authentication : public AuthenticationBase, public drogon::DrObject<T>
{
  public:
    /**
     *  Do not automatically create an instance.
     *  @see drogon::DrObject<T>
     */
    static constexpr bool isAutoCreation{false};

  private:
    class Emm
    {
      public:
        Emm()
        {
            setLambda();
        }

        const std::string &className() const
        {
            static std::string className =
                drogon::DrClassMap::demangle(typeid(T).name());
            return className;
        }

        void setLambda()
        {
            map[className()] = [] { return new T; };
        }
    };

    static Emm emm;

    virtual void *touch()
    {
        return &emm;
    }
};

template <typename T>
typename Authentication<T>::Emm Authentication<T>::emm;

/**
 *  @class Buldrokkas_tee
 *  @brief Buldrokkas_tee plug-in.
 *  @details Inherit from `drogon::Plugin` and provides authorization management
 *  @author tanglong3bf
 *  @date 2024-12-18
 *  @since 0.0.1
 */
class Buldrokkas_tee : public drogon::Plugin<Buldrokkas_tee>,
                       public std::enable_shared_from_this<Buldrokkas_tee>

{
  public:
    Buldrokkas_tee() = default;

    /// This method must be called by drogon to initialize and start the
    /// plugin. It must be implemented by the user.
    void initAndStart(const Json::Value &) override;

    /// This method must be called by drogon to shutdown the plugin.
    /// It must be implemented by the user.
    void shutdown() override;

  private:
    std::shared_ptr<UserServiceBase> userService_;
    std::shared_ptr<PasswordEncoderBase> passwordEncoder_;
    std::vector<std::shared_ptr<drogon::HttpFilterBase>> filters_;
};
};  // namespace tl::secure
