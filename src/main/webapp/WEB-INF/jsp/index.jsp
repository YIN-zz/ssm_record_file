<%--
  Created by IntelliJ IDEA.
  User: 椰子
  Date: 2019/6/28
  Time: 20:31
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
<html>
<head>
    <title>Title</title>
    <script src="/js/jquery-3.4.1.js"></script>
    <script>
        $(function(){
            $(".del").click(function(){
                var id = $(this).attr("id");
                $.post("/del/"+id,{_method:"delete"},function(d){
                    alert(d);
                    $("#tr" + id).remove();
                },"text");
            });
        });
    </script>
</head>
<body>
欢迎${sessionScope.user.username}<a href="/leave">添加请假</a><a href="/leaveList">审批假条</a> &nbsp;<a href="exit">退出</a>
<table>
    <tr>
        <th>序号</th>
        <th>姓名</th>
        <th>生日</th>
        <th>性别</th>
        <th>职业</th>
        <th>住所</th>
        <th>电话</th>

        <th>管理员名称</th>
        <th>操作</th>
    </tr>
<c:forEach items="${pageInfo.list}" var="pro" varStatus="i">
    <tr id="tr${pro.id}">
        <td>${i.count}</td>
        <td>${pro.name}</td>
        <td>${pro.birthday}</td>
        <td>${pro.gender}</td>
        <td>${pro.career}</td>
        <td>${pro.address}</td>
        <td>${pro.mobile}</td>
        <td><a href="/detail?id=${pro.id}">详细</a>|
            <a href="/alterPage?id=${pro.id}">修改</a>|
            <shiro:hasPermission name="user:delete">
                 <a href="#" id="${pro.id}" class="del">删除</a></td>
            </shiro:hasPermission>

    </tr>

</c:forEach>
</table>
<c:if test="${pageInfo.isFirstPage}">
    首页
    上一页
</c:if>
<c:if test="${!pageInfo.isFirstPage}">
    <a href="index?pageNum=${pageInfo.firstPage}">首页</a>
    <a href="index?pageNum=${pageInfo.prePage}">上一页</a>
</c:if>


<c:if test="${!pageInfo.isLastPage}">
    <a href="index?pageNum=${pageInfo.nextPage}">下一页</a>
    <a href="index?pageNum=${pageInfo.lastPage}">尾页</a>
</c:if>

<c:if test="${pageInfo.isLastPage}">
    下一页
    尾页
</c:if>

&nbsp;<span>跳转到：</span>

    <select name="pageNum" onchange="window.location=this.value;">
        <option>${pageInfo.pageNum}</option>
        <c:forEach begin="1" end="${pageInfo.pages}" var="i">
            <option value="index?pageNum=${i}">${i}</option>
        </c:forEach>
    </select>
<span>页</span>

&nbsp;<span>当前是第${pageInfo.pageNum}页/共${pageInfo.pages}页</span>
</body>
</html>
