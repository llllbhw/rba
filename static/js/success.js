// 跳转到仪表板
document.getElementById('go-to-dashboard').addEventListener('click', function() {
    window.location.href = '/templates/dashboard.html'; // 重定向到仪表板页面
});

// 登出
document.getElementById('logout').addEventListener('click', function() {
    window.location.href = '/templates/login.html'; // 重定向到登出页面或清除用户会话
});
