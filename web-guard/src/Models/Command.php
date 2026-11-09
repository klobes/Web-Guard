<?php

namespace Botble\WebGuard\Models;

use Illuminate\Database\Eloquent\Model;

class Command extends Model
{
    protected $table = 'wg_commands';
    protected $guarded = [];
    protected $casts = ['payload' => 'array', 'result' => 'array', 'lease_until' => 'datetime'];
}
