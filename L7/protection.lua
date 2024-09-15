-- 404 Shield Layer 7 

local challenge_duration = 1800
local max_requests = 100
local cookie_name = "_shield"
local valid_cookie_name = "_shield_valid"
local challenge_url = "/"
local fail_url = "/failed"
local clear_url = "/shield/clear"
local extended_cookie_duration = 1800 

local token_store = ngx.shared.token_store
local valid_store = ngx.shared.valid_store
local rate_limit_store = ngx.shared.rate_limit_store
local threat_store = ngx.shared.threat_store

local whitelist = {
    "5.161.104.126",
    "2a01:4ff:f0:b85c::1",
    "2a01:4ff:f0:b85c::/64",
    "2a01:4ff:f0:b85c"
}

local function ip_in_list(ip, list)
    for _, value in ipairs(list) do
        if type(value) == "string" and value == ip then
            return true
        elseif type(value) == "table" and ngx.re.match(ip, value, "ijo") then
            return true
        end
    end
    return false
end

local function generate_ray_id(length)
    local chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    local ray_id = {}
    for i = 1, length do
        local index = math.random(1, #chars)
        table.insert(ray_id, chars:sub(index, index))
    end
    return table.concat(ray_id)
end

local function generate_challenge_cookie_value()
    local random_ip = math.random(1, 255) .. "." .. math.random(1, 255) .. "." .. math.random(1, 255) .. "." .. math.random(1, 255)
    local random_domain = "www." .. generate_ray_id(8) .. ".com"
    local random_value = generate_ray_id(40)
    return random_ip .. "." .. random_domain .. "." .. random_value
end

local function set_challenge_cookies(challenge_token, extended)
    local max_age = extended and extended_cookie_duration or challenge_duration
    ngx.header["Set-Cookie"] = cookie_name .. "=" .. generate_challenge_cookie_value() .. "; Path=/; HttpOnly; Secure; Max-Age=" .. max_age .. ";"
    ngx.header["Set-Cookie"] = valid_cookie_name .. "=" .. challenge_token .. "; Path=/; HttpOnly; Secure; Max-Age=" .. max_age .. ";"
end

local function store_token(ip, token)
    token_store:set(ip, token, challenge_duration)
end

local function is_token_valid(ip, token)
    local stored_token = token_store:get(ip)
    return stored_token == token
end

local function store_valid_token(ip, token)
    valid_store:set(ip, token, challenge_duration)
end

local function get_valid_token(ip)
    return valid_store:get(ip)
end

local function is_all_cookies_valid()
    local shield_cookie = ngx.var["cookie_" .. cookie_name]
    local valid_cookie = ngx.var["cookie_" .. valid_cookie_name]
    local ip = ngx.var.binary_remote_addr

    if not shield_cookie or not valid_cookie then
        return false
    end

    local challenge_token = valid_cookie:match("([^%.]+)$")
    return is_token_valid(ip, challenge_token)
end

local function detect_sql_injection(user_agent, uri)
    local patterns = {
        "union.*select.*from",
        "select.*from.*information_schema.tables",
        "select.*from.*mysql.db",
        "select.*from.*pg_tables",
        "select.*from.*sys.objects",
        "drop.*table.*"
    }

    for _, pattern in ipairs(patterns) do
        if ngx.re.match(uri, pattern, "ijo") or ngx.re.match(user_agent, pattern, "ijo") then
            return true
        end
    end

    return false
end

local function detect_xss(uri)
    local patterns = {
        "<script.*>.*</script>",
        "javascript:",
        "data:text/html",
        "onerror=",
        "onload="
    }

    for _, pattern in ipairs(patterns) do
        if ngx.re.match(uri, pattern, "ijo") then
            return true
        end
    end

    return false
end


local function apply_custom_rules(threat_score)
    if threat_score > 10 then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header.content_type = "text/html"
        ngx.say([[
            <!DOCTYPE html>
            <html>
            <head>
                <title>403 Forbidden</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                    h1 { font-size: 36px; color: #ff0000; }
                </style>
            </head>
            <body>
                <h1>403 Forbidden</h1>
                <p>Your request has been blocked due to high threat score.</p>
                <p>Powered by 404 Shield</p>
            </body>
            </html>
        ]])
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

local function handle_challenge()
    local client_ip = ngx.var.binary_remote_addr
    local ray_id = generate_ray_id(16)
    local challenge_token = generate_ray_id(32)
    store_token(client_ip, challenge_token)
    ngx.header["Ray-ID"] = ray_id
    set_challenge_cookies(challenge_token)
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html"
    ngx.say([[
        <!DOCTYPE html>
        <html>
        <head>
            <title>Checking your browser and Your Ip</title>
            <style>
                body { background-color: #f0f0f0; font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; text-align: center; margin: 0; }
                .container { max-width: 500px; padding: 40px; background: white; box-shadow: 0 0 15px rgba(0,0,0,0.1); border-radius: 8px; }
                .spinner { margin: 20px auto 30px; width: 40px; height: 40px; border: 4px solid rgba(0, 0, 0, 0.1); border-top-color: #3498db; border-radius: 50%; animation: spin 1s linear infinite; }
                @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
            </style>
            <script>
                function setCookie(name, value, seconds) {
                    var expires = "";
                    if (seconds) {
                        var date = new Date();
                        date.setTime(date.getTime() + (seconds * 1000));
                        expires = "; expires=" + date.toUTCString();
                    }
                    document.cookie = name + "=" + (value || "") + expires + "; path=/";
                }

                function checkChallenge() {
                    var shieldCookie = document.cookie.replace(/(?:(?:^|.*;\s*)]] .. cookie_name .. [[\s*\=\s*([^;]*).*$)|^.*$/, "$1");
                    var validCookie = document.cookie.replace(/(?:(?:^|.*;\s*)]] .. valid_cookie_name .. [[\s*\=\s*([^;]*).*$)|^.*$/, "$1");

                    if (!shieldCookie || !validCookie) {
                        var challengeToken = "]] .. generate_ray_id(32) .. [[";
                        setCookie(']] .. cookie_name .. [[', challengeToken, ]] .. extended_cookie_duration .. [[);
                        setCookie(']] .. valid_cookie_name .. [[', challengeToken, ]] .. extended_cookie_duration .. [[);
                        window.location.reload();
                    }
                }

                window.onload = function() {
                    checkChallenge();
                };
            </script>
        </head>
        <body>
            <div class="container">
                <div class="spinner"></div>
                <h2>Checking your browser and Your Ip</h2>
                <p>This process is automatic. Your browser will redirect to your requested content shortly. Please allow a few seconds...</p>
                <p>Powered by 404 Shield</p>
            </div>
        </body>
        </html>
    ]])
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function handle_fail()
    local ray_id = generate_ray_id(16)
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "text/html"
    ngx.say([[
        <!DOCTYPE html>
        <html>
        <head>
            <title>403 Forbidden</title>
            <style>
                body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                h1 { font-size: 36px; color: #ff0000; }
            </style>
        </head>
        <body>
            <h1>403 Forbidden</h1>
            <p>Your request has been blocked due to suspicious activity.</p>
            <p>Ray-ID: ]] .. ray_id .. [[</p>
            <p>Powered by 404 Shield</p>
        </body>
        </html>
    ]])
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

local function is_whitelisted(ip)
    return ip_in_list(ip, whitelist)
end

local function clear_all_data()
    token_store:flush_all()
    valid_store:flush_all()
    rate_limit_store:flush_all()
end

local function handle_clear()
    local client_ip = ngx.var.binary_remote_addr
    if not is_whitelisted(client_ip) then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say("403 Forbidden: Access Denied")
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    clear_all_data()
    ngx.status = ngx.HTTP_OK
    ngx.say("Data cleared successfully")
    ngx.exit(ngx.HTTP_OK)
end

local function rate_limit_check(ip)
    local current_requests = rate_limit_store:get(ip)
    if not current_requests then
        rate_limit_store:set(ip, 1, 180)
    elseif current_requests >= max_requests then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header.content_type = "text/html"
        ngx.say([[
            <!DOCTYPE html>
            <html>
            <head>
                <title>Rate Limit Exceeded</title>
                <style>
                    body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                    h1 { font-size: 36px; color: #ff0000; }
                </style>
            </head>
            <body>
                <h1>403 Forbidden</h1>
                <p>Rate limit exceeded. Please wait 3 minutes before retrying.</p>
            </body>
            </html>
        ]])
        ngx.exit(ngx.HTTP_FORBIDDEN)
    else
        rate_limit_store:incr(ip, 1)
    end
end

local function apply_security()
    local client_ip = ngx.var.binary_remote_addr
    local user_agent = ngx.var.http_user_agent
    local uri = ngx.var.uri
    local referrer = ngx.var.http_referer
    local threat_score = 0

    if ngx.var.uri == clear_url then
        handle_clear()
        return
    end

    if is_whitelisted(client_ip) then
        ngx.log(ngx.ERR, "Client IP is whitelisted: " .. client_ip)
        ngx.status = ngx.HTTP_OK
        return
    end

    rate_limit_check(client_ip)

  

    apply_custom_rules(threat_score)

    if not is_all_cookies_valid() then
        handle_challenge()
    end

    if ngx.var.http_user_agent:match("bot") or ngx.var.ssl_protocol == "TLSv1.0" then
        handle_fail()
    end

    ngx.status = ngx.HTTP_OK
end

apply_security()
