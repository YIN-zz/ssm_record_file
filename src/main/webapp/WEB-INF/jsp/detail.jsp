<%--
  Created by IntelliJ IDEA.
  User: 椰子
  Date: 2019/6/29
  Time: 9:50
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Title</title>
</head>
<body>
<h2>档案详情</h2>
<table>
    <tr>
        <td>编号</td>
        <td>${profile.id}</td>
    </tr>
    <tr>
        <td>姓名</td>
        <td>${profile.name}</td>
    </tr>
    <tr>
        <td>生日</td>
        <td>${profile.birthday}</td>
    </tr>
    <tr>
        <td>性别</td>
        <td>${profile.gender}</td>
    </tr>
    <tr>
        <td>职业</td>
        <td>${profile.career}</td>
    </tr>
    <tr>
        <td>地址</td>
        <td>${profile.address}</td>
    </tr>
    <tr>
        <td>电话</td>
        <td>${profile.mobile}</td>
    </tr>
    <tr>
        <td><img src="${profile.picture}"></td>
        <td></td>
    </tr>
</table>
<a href="index">返回</a>

</body>
</html>
