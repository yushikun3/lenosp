package com.len.config;

import com.len.core.BlogRealm;
import com.len.core.MyBasicHttpAuthenticationFilter;
import com.len.core.filter.PermissionFilter;
import com.len.core.filter.VerfityCodeFilter;
import com.len.core.shiro.LoginRealm;
import com.len.core.shiro.RetryLimitCredentialsMatcher;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.*;

/**
 * @author zhuxiaomeng
 * @date 2018/1/1.
 * @email 154040976@qq.com
 * spring shiro
 * 元旦快乐：code everybody
 */
@Configuration
public class ShiroConfig {

    @Bean
    public RetryLimitCredentialsMatcher getRetryLimitCredentialsMatcher() {
//    RetryLimitCredentialsMatcher rm = new RetryLimitCredentialsMatcher(getCacheManager(),2);
        RetryLimitCredentialsMatcher rm = new RetryLimitCredentialsMatcher(getCacheManager());
        rm.setHashAlgorithmName("md5");
        rm.setHashIterations(4);
        return rm;

    }

   /* @Bean
    public BlogRetryLimitCredentialsMatcher getBlogRetryLimitCredentialsMatcher() {
        BlogRetryLimitCredentialsMatcher rm = new BlogRetryLimitCredentialsMatcher(getCacheManager());
        rm.setHashAlgorithmName("md5");
        rm.setHashIterations(4);
        return rm;

    }*/

    @Bean(name = "userLoginRealm")
    public LoginRealm getLoginRealm() {
        LoginRealm realm = new LoginRealm();
        realm.setCredentialsMatcher(getRetryLimitCredentialsMatcher());
        return realm;
    }

    @Bean(name = "blogLoginRealm")
    public BlogRealm blogLoginRealm() {
        return new BlogRealm();
    }

    @Bean
    public EhCacheManager getCacheManager() {
        EhCacheManager ehCacheManager = new EhCacheManager();
        ehCacheManager.setCacheManagerConfigFile("classpath:ehcache/ehcache.xml");
        return ehCacheManager;
    }

    @Bean
    public LifecycleBeanPostProcessor getLifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

    @Bean
    public AtLeastOneSuccessfulStrategy getAtLeastOneSuccessfulStrategy() {
        return new AtLeastOneSuccessfulStrategy();
    }

    @Bean
    public MyModularRealmAuthenticator getMyModularRealmAuthenticator() {
        MyModularRealmAuthenticator authenticator = new MyModularRealmAuthenticator();
        authenticator.setAuthenticationStrategy(getAtLeastOneSuccessfulStrategy());
        return authenticator;
    }

    @Bean(name = "securityManager")
    public SecurityManager getSecurityManager(@Qualifier("userLoginRealm") LoginRealm loginRealm,
                                              @Qualifier("blogLoginRealm") BlogRealm blogLoginRealm) {
        DefaultWebSecurityManager dwm = new DefaultWebSecurityManager();
        List<Realm> loginRealms = new ArrayList<>();
        dwm.setAuthenticator(getMyModularRealmAuthenticator());
        loginRealm.setName("UserLogin");
        blogLoginRealm.setName("BlogLogin");
        loginRealms.add(loginRealm);
        loginRealms.add(blogLoginRealm);
        dwm.setRealms(loginRealms);
        dwm.setCacheManager(getCacheManager());
        dwm.setSessionManager(defaultWebSessionManager());
        return dwm;
    }
    ////和授权相关
    @Bean
    public PermissionFilter getPermissionFilter() {
        return new PermissionFilter();
    }

    @Bean
    public MyBasicHttpAuthenticationFilter getAuthenticationFilter() {
        return new MyBasicHttpAuthenticationFilter();
    }

    @Bean
    public VerfityCodeFilter getVerfityCodeFilter() {
        VerfityCodeFilter vf = new VerfityCodeFilter();
        vf.setFailureKeyAttribute("shiroLoginFailure");
        vf.setJcaptchaParam("code");
        vf.setVerfitiCode(true);
        return vf;
    }
    //权限动态加载 过滤器
    @Bean(name = "shiroFilter")
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") SecurityManager securityManager) {
        ShiroFilterFactoryBean sfb = new ShiroFilterFactoryBean();
        sfb.setSecurityManager(securityManager);
        // 如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面
        sfb.setLoginUrl("/login");
        //未授权界面;
        sfb.setUnauthorizedUrl("/goLogin");
        //自定义拦截器
        Map<String, Filter> filters = new HashMap<>();
        //和授权相关
        filters.put("per", getPermissionFilter());
        //拦截码拦截
        filters.put("verCode", getVerfityCodeFilter());
        //认证有关
        filters.put("jwt", getAuthenticationFilter());
        //放入容器工厂中
        sfb.setFilters(filters);
        //拦截器
        Map<String, String> filterMap = new LinkedHashMap<>();
        filterMap.put("/login", "verCode,anon");
        filterMap.put("/blogLogin", "verCode,anon");
        //anon:所有url都都可以匿名访问
        filterMap.put("/getCode", "anon");
        // 配置不会被拦截的链接 顺序判断 anon:所有url都都可以匿名访问
        filterMap.put("/img/**", "anon");
        //配置退出 过滤器,其中的具体的退出代码Shiro已经替我们实现了
        filterMap.put("/logout", "logout");
        // 配置不会被拦截的链接 顺序判断 anon:所有url都都可以匿名访问
        filterMap.put("/plugin/**", "anon");
        // 配置不会被拦截的链接 顺序判断 anon:所有url都都可以匿名访问
        filterMap.put("/user/**", "per");
        // 配置不会被拦截的链接 顺序判断 anon:所有url都都可以匿名访问
        filterMap.put("/blog-admin/**", "jwt");
        // 配置不会被拦截的链接 顺序判断 anon:所有url都都可以匿名访问
        filterMap.put("/blog/**", "anon");
        //<!-- 过滤链定义，从上向下顺序执行，一般将/**放在最为下边 -->:这是一个坑呢，一不小心代码就不好使了;
        //<!-- authc:所有url都必须认证通过才可以访问; anon:所有url都都可以匿名访问-->
        filterMap.put("/**", "authc");
        //将过滤规则放入工厂
        sfb.setFilterChainDefinitionMap(filterMap);
        return sfb;
    }

    @Bean
    public DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator advisorAutoProxyCreator = new DefaultAdvisorAutoProxyCreator();
        advisorAutoProxyCreator.setProxyTargetClass(true);
        return advisorAutoProxyCreator;
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor getAuthorizationAttributeSourceAdvisor(@Qualifier("securityManager") SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor as = new AuthorizationAttributeSourceAdvisor();
        as.setSecurityManager(securityManager);
        return as;
    }

    @Bean
    public DefaultWebSessionManager defaultWebSessionManager() {
        DefaultWebSessionManager defaultWebSessionManager = new DefaultWebSessionManager();
        defaultWebSessionManager.setSessionIdCookieEnabled(true);
        defaultWebSessionManager.setGlobalSessionTimeout(21600000);
        defaultWebSessionManager.setDeleteInvalidSessions(true);
        defaultWebSessionManager.setSessionValidationSchedulerEnabled(true);
        defaultWebSessionManager.setSessionIdUrlRewritingEnabled(false);
        return defaultWebSessionManager;
    }
/*
  @Bean
  public FilterRegistrationBean delegatingFilterProxy(){
    FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean();
    DelegatingFilterProxy proxy = new DelegatingFilterProxy();
    proxy.setTargetFilterLifecycle(true);
    proxy.setTargetBeanName("shiroFilter");

    filterRegistrationBean.setFilter(proxy);
    return filterRegistrationBean;
  }*/


}
