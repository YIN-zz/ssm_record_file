package com.qf.realm;

import com.qf.service.UserService;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.Set;

/**
 * author:殷壮壮
 * date:
 * info:
 */
public class UserRealm extends AuthorizingRealm {
  @Autowired
    private UserService userService;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //获取当前账户的用户名
        String username = (String )principalCollection.getPrimaryPrincipal();
        //根据用户名查询数据库中的账户表，获取到该账户对应的角色列表
        Set<String > strings = new HashSet<String>();
        strings.add("role1");
        //根据角色列表分别从数据库的角色权限表中查询出该角色下对应的权限列表
        Set<String > strings1 = new HashSet<String>();
        /*strings1.add("user:add");*/
        strings1.add("user:update");
        strings1.add("user:delete");
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo(strings);
        simpleAuthorizationInfo.setStringPermissions(strings1);
        return simpleAuthorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String username =(String )authenticationToken.getPrincipal();
        //根据数据库中的用户名查询密码
        String password = userService.getPassword(username);
        SimpleAuthenticationInfo simpleAuthoricationInfo =
                new SimpleAuthenticationInfo(username,password,"UserRealm");

        return null;
    }
}
