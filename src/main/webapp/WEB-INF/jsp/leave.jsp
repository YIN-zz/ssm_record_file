<%--
  Created by IntelliJ IDEA.
  User: chris
  Date: 2019/7/10
  Time: 11:01
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title>Title</title>
</head>
<body>
<form action="/addLeave" method="post">
    开始时间：<input type="text" name="startDate"><br>
    结束时间：<input type="text" name="endDate"><br>
    请假理由：<input type="text" name="reason"><br>
    <input type="submit" value="提交">
</form>

</body>
</html>
