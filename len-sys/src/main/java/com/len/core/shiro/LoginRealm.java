package com.len.core.shiro;

import com.len.base.CurrentMenu;
import com.len.base.CurrentRole;
import com.len.base.CurrentUser;
import com.len.entity.SysUser;
import com.len.service.SysUserService;
import com.len.util.BeanUtil;
import com.len.util.JWTUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * @author zhuxiaomeng
 * @date 2017/12/4.
 * @email 154040976@qq.com
 */
@Service
public class LoginRealm extends AuthorizingRealm {

    @Autowired
    private SysUserService userService;


    /**
     * 获取授权
     *授权操作
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //principalCollection用户的凭证信息
        //SimpleAuthorizationInfo 认证方法返回封装认证信息中第一个参数 : 用户信息（username）
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        //当前登录用户名信息：用户凭证
        CurrentUser user = (CurrentUser) principalCollection.getPrimaryPrincipal();

        Set<String> realmNames = principalCollection.getRealmNames();
        List<String> realmNameList = new ArrayList<>(realmNames);
        if ("BlogLogin".equals(realmNameList.get(0))) {
            String[] roles = JWTUtil.getRoles(user.getUsername());
            assert roles != null;
            for (String role : roles) {
                info.addRole(role);
            }
        } else {
            //根据用户获取角色 根据角色获取所有按钮权限
            //获取当前用户对象
            CurrentUser cUser = (CurrentUser) Principal.getSession().getAttribute("currentPrincipal");

            for (CurrentRole cRole : cUser.getCurrentRoleList()) {
                info.addRole(cRole.getId());
            }
            for (CurrentMenu cMenu : cUser.getCurrentMenuList()) {
                if (!StringUtils.isEmpty(cMenu.getPermission())) {
                    info.addStringPermission(cMenu.getPermission());
                }
            }
        }
        //返回用户在数据库中拥有的权限
        return info;
    }

    /**
     * 获取认证
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */

    //参数一:验证令牌  参数二：
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
            throws AuthenticationException {
        //获取用户的输入的账号.
        String username = (String) authenticationToken.getPrincipal();
        SysUser s = null;
        try {
            //通过username从数据库中查找 User对象，如果找到，没找到.
            //实际项目中，这里可以根据实际情况做缓存，如果不做，Shiro自己也是有时间间隔机制，2分钟内不会重复执行该方法
            s = userService.login(username);
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (s == null) {
            throw new UnknownAccountException("账户密码不正确");
        }
        CurrentUser user=new CurrentUser();
        //非空拷贝对象
        BeanUtil.copyNotNullBean(s,user);
        user.setPassword(null);
        userService.setMenuAndRoles(username);
        ByteSource byteSource = ByteSource.Util.bytes(username);
        //参数一:数据库中查到的user对象 ，参数二:s.getPassword(),用户密码 ，参数三:
        return new SimpleAuthenticationInfo(user, s.getPassword(), byteSource, getName());
    }
}
