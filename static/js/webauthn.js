// 为表单绑定提交事件
document.getElementById('verifyForm').addEventListener('submit', function(event) {
    event.preventDefault(); // 阻止默认表单提交行为

    const verificationCode = document.getElementById('verification-code').value;
    
    // 在这里可以通过AJAX/Fetch调用后端验证逻辑，或直接进行简化的本地模拟
    if (isValidVerificationCode(verificationCode)) {
        // 验证通过，跳转到成功页面或执行其他操作
        window.location.href = '/templates/success.html';
    } else {
        // 显示错误提示信息
        document.getElementById('error-message').style.display = 'block';
    }
});

// 模拟验证函数
function isValidVerificationCode(code) {
    // 这里只是示例写法，实际应通过服务器端验证
    return code === '123456';
}
