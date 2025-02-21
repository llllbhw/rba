document.addEventListener('DOMContentLoaded', () => {
    runEncryptionLogic();
});

function runEncryptionLogic() {
    console.log("Encryption logic is ready.");
    // 在这里执行你需要的初始化操作...
}

// 特征数量字典，可根据后端实际处理逻辑调整
const uniqueValueCounts = {
    "OS Name and Version": 653,
    "Browser Name and Version": 4549,
    "Device Type": 3,
    "IP Address": 3512330,
    "Country": 229,
    "Region": 2638,
    "City": 38885,
    "ASN": 12955,
    "User Agent String": 420952,
    "Login Timestamp": 1048575,
    "User ID": 1048575,
    "Round-Trip Time [ms]": 9113
};

// 表单提交时收集浏览器/系统/IP 等信息并发送到后端
async function attachBrowserAndIpInfo(event) {
    event.preventDefault(); // 阻止默认提交，便于插入自定义逻辑

    // 记录开始时间，用以计算RTT
    const loginTimestamp = Date.now();

    /******************************************************
     * 1. 提取并哈希处理用户代理(User Agent)信息
     ******************************************************/
    const userAgentString = navigator.userAgent;
    console.log('User Agent:', userAgentString);
    const userAgentHash = hashData(userAgentString); 
    const userAgentPositionVector = generatePositionVectorForFeature(userAgentHash, "User Agent String");
    const encryptedUserAgentPositionVector = encryptPositionVector(userAgentPositionVector);

    /******************************************************
     * 2. 提取并哈希处理操作系统信息
     ******************************************************/
    const osInfo = extractOsInfo(userAgentString);
    console.log('OS Info:', osInfo);
    const osHash = hashData(osInfo);
    const osPositionVector = generatePositionVectorForFeature(osHash, "OS Name and Version");
    const encryptedOsPositionVector = encryptPositionVector(osPositionVector);

    /******************************************************
     * 3. 提取并哈希处理浏览器信息
     ******************************************************/
    const browserInfo = extractBrowserInfo(userAgentString);
    console.log('Browser Info:', browserInfo);
    const browserHash = hashData(browserInfo);
    const browserPositionVector = generatePositionVectorForFeature(browserHash, "Browser Name and Version");
    const encryptedBrowserPositionVector = encryptPositionVector(browserPositionVector);

    /******************************************************
     * 4. 提取并哈希处理设备类型
     ******************************************************/
    const deviceType = extractDeviceType(userAgentString);
    console.log('Device Type:', deviceType);
    const deviceHash = hashData(deviceType);
    const devicePositionVector = generatePositionVectorForFeature(deviceHash, "Device Type");
    const encryptedDevicePositionVector = encryptPositionVector(devicePositionVector);

    /******************************************************
     * 5. 获取 IP 位置信息 并进行哈希/加密
     ******************************************************/
    try {
        // 示例：使用 ipinfo.io 获取地理位置信息
        const response = await fetch('https://ipinfo.io/json?token=4e63a4ab721aa9');
        if (!response.ok) {
            throw new Error(`HTTP error! Status: ${response.status}`);
        }
        const data = await response.json();
        console.log('IP Info:', data);

        // IP
        const ipHash = hashData(data.ip);
        const ipPositionVector = generatePositionVectorForFeature(ipHash, "IP Address");
        const encryptedIpPositionVector = encryptPositionVector(ipPositionVector);
        // document.getElementById('user_ip').value = JSON.stringify(encryptedIpPositionVector);

        // ASN
        const asnInfo = extractASN(data.org);
        console.log('ASN:', asnInfo);
        const asnHash = hashData(asnInfo);
        const asnPositionVector = generatePositionVectorForFeature(asnHash, "ASN");
        const encryptedAsnPositionVector = encryptPositionVector(asnPositionVector);
        // document.getElementById('asn').value = JSON.stringify(encryptedAsnPositionVector);

        // Country
        const countryHash = hashData(data.country);
        const countryPositionVector = generatePositionVectorForFeature(countryHash, "Country");
        const encryptedCountryPositionVector = encryptPositionVector(countryPositionVector);

        // Region
        const regionHash = hashData(data.region);
        const regionPositionVector = generatePositionVectorForFeature(regionHash, "Region");
        const encryptedRegionPositionVector = encryptPositionVector(regionPositionVector);

        // City
        const cityHash = hashData(data.city);
        const cityPositionVector = generatePositionVectorForFeature(cityHash, "City");
        const encryptedCityPositionVector = encryptPositionVector(cityPositionVector);

        // 6. 计算往返时间RTT
        const roundTripTime = Date.now() - loginTimestamp;
        console.log('Round-Trip Time:', roundTripTime, 'ms');

        /******************************************************
         * 将这些信息传给后端
         * 可以先通过 HTML 表单的方式提交，也可以用 Ajax 
         ******************************************************/
        event.target.submit(); // 让表单提交到指定后端地址
        
        // 若你想通过Fetch向后端接口发送加密向量
        const response_score = await fetch('/compute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                encryptedOsPositionVector,
                encryptedBrowserPositionVector,
                encryptedDevicePositionVector,
                encryptedUserAgentPositionVector,
                encryptedIpPositionVector,
                encryptedCountryPositionVector,
                encryptedRegionPositionVector,
                encryptedCityPositionVector,
                encryptedAsnPositionVector,
                loginTimestamp,
                username: document.getElementById('username').value,
            }),
        });

        const result = await response_score.json();
        console.log("Server computed RBA score => ", result);

        // 解密后再传给后端(示例)
        const decryptedResult = decryptResult(result);
        await fetch('/auth', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ decryptedResult }),
        });

    } catch (error) {
        console.error('Error fetching IP information:', error);
        // 根据实际需要处理错误情况
    }
}


/**********************************************************
 * 以下为各类辅助函数
 **********************************************************/

// 将字符串用 CryptoJS.SHA256 进行哈希
function hashData(data) {
    return CryptoJS.SHA256(data).toString();
}

// 从哈希中得到一个索引，再根据该索引生成单热(One-hot)向量
function generatePositionVectorForFeature(featureHash, featureName) {
    const totalValues = uniqueValueCounts[featureName];
    const positionIndex = getIndexFromHash(featureHash, totalValues);
    return createPositionVector(totalValues, positionIndex);
}

// 简单截取哈希前5位并转16进制 => 取模
function getIndexFromHash(hash, totalValues) {
    return parseInt(hash.substring(0, 5), 16) % totalValues;
}

// 生成单热向量
function createPositionVector(totalValues, positionIndex) {
    const positionVector = new Array(totalValues).fill(0);
    if (positionIndex >= 0 && positionIndex < totalValues) {
        positionVector[positionIndex] = 1;
    }
    return positionVector;
}

// 示例加密函数，真正加密需使用 seal 对象
function encryptPositionVector(positionVector) {
    // 这里演示：原样返回
    // 你若使用 SEAL.js，则可在此处用 encryptor、batchEncoder 等将其加密
    return positionVector;
}

// 将后端加密计算的结果再解密
function decryptResult(encryptedData) {
    // 这里仅做示例，真实环境需调用 seal 解密
    return encryptedData;
}

// 解析 User Agent 获取 OS 信息
function extractOsInfo(userAgent) {
    if (userAgent.includes('Windows NT 10.0')) return 'Windows 10';
    if (userAgent.includes('Windows NT 6.3'))  return 'Windows 8.1';
    if (userAgent.includes('Windows NT 6.2'))  return 'Windows 8';
    if (userAgent.includes('Windows NT 6.1'))  return 'Windows 7';
    if (userAgent.includes('Mac OS X'))       return 'macOS';
    if (userAgent.includes('Android'))        return 'Android';
    if (userAgent.includes('iPhone OS'))      return 'iOS';
    if (userAgent.includes('Linux'))          return 'Linux';
    return 'Unknown OS';
}

// 解析 User Agent 获取浏览器信息
function extractBrowserInfo(userAgent) {
    if (userAgent.includes('Chrome/') && userAgent.includes('Safari/')) 
        return 'Chrome';
    if (userAgent.includes('Firefox/')) 
        return 'Firefox';
    if (userAgent.includes('Safari/') && userAgent.includes('Version/')) 
        return 'Safari';
    if (userAgent.includes('Edg/')) 
        return 'Edge';
    if (userAgent.includes('MSIE ')) 
        return 'Internet Explorer';
    if (userAgent.includes('Trident/')) 
        return 'Internet Explorer';
    return 'Unknown Browser';
}

// 解析 User Agent 获取设备类型
function extractDeviceType(userAgent) {
    if (userAgent.includes('Mobi') || userAgent.includes('Android') || userAgent.includes('iPhone')) {
        return 'Mobile';
    } else if (userAgent.includes('Tablet') || userAgent.includes('iPad')) {
        return 'Tablet';
    } else {
        return 'Desktop';
    }
}

// 解析 ASN
function extractASN(asString) {
    if (asString && asString.includes('AS')) {
        const match = asString.match(/AS(\d+)/);
        return match ? match[1] : 'N/A';
    }
    return 'N/A';
}
