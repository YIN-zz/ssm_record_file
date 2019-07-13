<%--
  Created by IntelliJ IDEA.
  User: 椰子
  Date: 2019/6/29
  Time: 10:06
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Title</title>
</head>
<body>
<h2>修改档案</h2>
<form action="alter" method="post" enctype="multipart/form-data">
    <input type="hidden" name="id" value="${profile.id}">
    <table>
        <tr>
            <td>编号</td>
            <td>${profile.id}</td>
        </tr>
        <tr>
            <td>姓名</td>
            <td><input type="text" name="name" value="${profile.name}"></td>
        </tr>
        <tr>
            <td>生日</td>
            <td><input type="date" name="birthday" value="${profile.birthday}"></td>
        </tr>
        <tr>
            <td>性别</td>
            <td><select name="gender">
                <option value="男">男</option>
                <option value="女">女</option>
            </select>
        </tr>
        <tr>
            <td>职业</td>
            <td><input type="text" name="career" value="${profile.career}"></td>
        </tr>
        <tr>
            <td>地址</td>
            <td><input type="text" name="address" value="${profile.address}"></td>
        </tr>
        <tr>
            <td>电话</td>
            <td><input type="text" name="mobile" value="${profile.mobile}"></td>
        </tr>
        <tr>
            <td><input type="file" name="file" value="${profile.picture}"></td>
            <td></td>
        </tr>
        <tr>
            <td><input type="submit" value="提交"></td>
            <td></td>
        </tr>
    </table>
</form>

<a href="index">返回</a>
</body>
</html>
