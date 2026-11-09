<?php

return [
    ['name' => 'plugins/web-guard::web-guard.perm_dashboard', 'flag' => 'web-guard.dashboard'],
    ['name' => 'plugins/web-guard::web-guard.perm_incidents', 'flag' => 'web-guard.incidents', 'parent_flag' => 'web-guard.dashboard'],
    ['name' => 'plugins/web-guard::web-guard.perm_bans', 'flag' => 'web-guard.bans', 'parent_flag' => 'web-guard.dashboard'],
    ['name' => 'plugins/web-guard::web-guard.perm_unban', 'flag' => 'web-guard.unban', 'parent_flag' => 'web-guard.bans'],
    ['name' => 'plugins/web-guard::web-guard.perm_allowlist', 'flag' => 'web-guard.allowlist', 'parent_flag' => 'web-guard.dashboard'],
    ['name' => 'plugins/web-guard::web-guard.perm_allowlist_edit', 'flag' => 'web-guard.allowlist.edit', 'parent_flag' => 'web-guard.allowlist'],
    ['name' => 'plugins/web-guard::web-guard.perm_paths', 'flag' => 'web-guard.paths', 'parent_flag' => 'web-guard.dashboard'],
    ['name' => 'plugins/web-guard::web-guard.perm_paths_edit', 'flag' => 'web-guard.paths.edit', 'parent_flag' => 'web-guard.paths'],
    ['name' => 'plugins/web-guard::web-guard.perm_settings', 'flag' => 'web-guard.settings', 'parent_flag' => 'web-guard.dashboard'],
    ['name' => 'plugins/web-guard::web-guard.perm_settings_edit', 'flag' => 'web-guard.settings.edit', 'parent_flag' => 'web-guard.settings'],
    ['name' => 'plugins/web-guard::web-guard.perm_setup', 'flag' => 'web-guard.setup', 'parent_flag' => 'web-guard.dashboard'],
    ['name' => 'plugins/web-guard::web-guard.perm_audit', 'flag' => 'web-guard.audit', 'parent_flag' => 'web-guard.dashboard'],
];
