<%--
&lt;%&ndash;
  Created by IntelliJ IDEA.
  User: 椰子
  Date: 2019/7/1
  Time: 10:49
  To change this template use File | Settings | File Templates.
&ndash;%&gt;
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Title</title>
</head>
<body>
<h2>添加档案</h2>
<form action="/add" method="post" enctype="multipart/form-data">
    <table>
        <tr>
            <td>姓名</td>
            <td><input type="text" name="name"></td>
        </tr>
        <tr>
            <td>生日</td>
            <td><input type="date" name="birthday"></td>
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
            <td><input type="text" name="career"></td>
        </tr>
        <tr>
            <td>地址</td>
            <td><input type="text" name="address"></td>
        </tr>
        <tr>
            <td>电话</td>
            <td><input type="text" name="mobile"></td>
        </tr>
        <tr>
            <td>头像</td>
            <td><input type="file" name="file"></td>
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
--%>
