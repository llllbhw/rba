// 通过按钮点击刷新统计数据
document.getElementById('refresh-btn').addEventListener('click', function() {
    refreshData();
});

document.getElementById('settings-btn').addEventListener('click', function() {
    alert('Navigating to settings...');
    // 在这里你可以实现跳转到设置页面的逻辑
    // window.location.href = '/settings'; // 例如：跳转到设置页面
});

// 模拟刷新数据
function refreshData() {
    // 假设通过API获取数据，这里用随机数代替
    const totalUsers = getRandomNumber(1000, 5000);
    const activeSessions = getRandomNumber(100, 500);
    const pendingRequests = getRandomNumber(0, 20);
    const errors = getRandomNumber(0, 5);

    document.getElementById('total-users').textContent = totalUsers;
    document.getElementById('active-sessions').textContent = activeSessions;
    document.getElementById('pending-requests').textContent = pendingRequests;
    document.getElementById('errors').textContent = errors;
}

// 模拟生成一个随机数字
function getRandomNumber(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// 页面加载时模拟数据刷新
window.onload = function() {
    refreshData();
};
