<?php

namespace Botble\WebGuard\Models;

use Illuminate\Database\Eloquent\Model;

class Configuration extends Model
{
    protected $table = 'wg_configurations';
    protected $guarded = [];
    protected $casts = ['desired' => 'array', 'applied' => 'array', 'revision' => 'integer', 'applied_revision' => 'integer'];
}
