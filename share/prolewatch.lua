local function shell_quote(value)
  assert(type(value) == "string", "shell_quote expects a string")
  assert(not value:find("\0", 1, true), "NUL is not allowed in shell arguments")
  return "'" .. value:gsub("'", "'\\''") .. "'"
end

local function valid_package_base(value)
  return type(value) == "string"
    and value:match("^[A-Za-z0-9@._+][A-Za-z0-9@._+-]*$") ~= nil
end

local function json_quote(value)
  assert(type(value) == "string", "json_quote expects a string")
  value = value:gsub("\\", "\\\\"):gsub('"', '\\"')
  value = value:gsub("[%z\1-\31]", function(character)
    local byte = string.byte(character)
    if byte == 8 then return "\\b" end
    if byte == 9 then return "\\t" end
    if byte == 10 then return "\\n" end
    if byte == 12 then return "\\f" end
    if byte == 13 then return "\\r" end
    return string.format("\\u%04x", byte)
  end)
  return '"' .. value .. '"'
end

local function json_string_array(values)
  assert(type(values) == "table", "context array is missing")
  local encoded = {}
  for _, value in ipairs(values) do
    table.insert(encoded, json_quote(value))
  end
  return "[" .. table.concat(encoded, ",") .. "]"
end

local function yay_context(data)
  local packages = {}
  assert(type(data.packages) == "table", "package context is missing")
  for _, package in ipairs(data.packages) do
    table.insert(packages, table.concat({
      "{\"name\":" .. json_quote(package.name),
      "\"version\":" .. json_quote(package.version),
      "\"local_version\":" .. json_quote(package.local_version),
      "\"reason\":" .. json_quote(package.reason),
      "\"upgrade\":" .. tostring(package.upgrade == true),
      "\"devel\":" .. tostring(package.devel == true) .. "}",
    }, ","))
  end
  local context = table.concat({
    "{\"version\":" .. json_quote(data.version),
    "\"last_modified\":" .. string.format("%.0f", data.last_modified),
    "\"installed\":" .. tostring(data.installed == true),
    "\"packages\":[" .. table.concat(packages, ",") .. "]",
    "\"depends\":" .. json_string_array(data.srcinfo.depends),
    "\"makedepends\":" .. json_string_array(data.srcinfo.makedepends),
    "\"checkdepends\":" .. json_string_array(data.srcinfo.checkdepends) .. "}",
  }, ",")
  if #context > 65536 then
    yay.abort("prolewatch: yay event context exceeds 64 KiB")
  end
  return context
end

-- Lua modules are loaded once by yay, so this marker is scoped to the real
-- transaction process without creating a spoofable file or environment flag.
local transaction_announced = false

local function run_scan(phase, event)
  if not valid_package_base(event.match) then
    yay.abort("prolewatch: invalid AUR package base")
  end
  if type(event.data) ~= "table" or type(event.data.dir) ~= "string" then
    yay.abort("prolewatch: missing package directory")
  end
  local command_parts = {
    "/usr/bin/prolewatch scan --interactive",
    "--phase", shell_quote(phase),
    "--dir", shell_quote(event.data.dir),
    "--package-base", shell_quote(event.match),
    "--yay-context", shell_quote(yay_context(event.data)),
  }
  if phase == "pre" and not transaction_announced then
    table.insert(command_parts, "--announce-transaction")
    transaction_announced = true
  end
  local command = table.concat(command_parts, " ")
  local first, _, third = os.execute(command)
  local success = first == true or first == 0
  if not success then
    local code = third or first or "unknown"
    yay.abort("prolewatch blocked " .. event.match .. " (exit " .. tostring(code) .. ")")
  end
end

yay.opt.clean_menu = true
yay.opt.diff_menu = true
yay.opt.edit_menu = true
yay.opt.pgp_fetch = true
yay.opt.redownload = "yes"
yay.opt.makepkg_bin = "/usr/bin/prolewatch-makepkg"
yay.opt.gpg_bin = "/usr/bin/prolewatch-gpg"

yay.create_autocmd("AURPreInstall", {
  desc = "fail-closed AUR recipe audit",
  callback = function(event)
    run_scan("pre", event)
  end,
})

yay.create_autocmd("AURPostDownload", {
  desc = "fail-closed downloaded source audit",
  callback = function(event)
    run_scan("post", event)
  end,
})
