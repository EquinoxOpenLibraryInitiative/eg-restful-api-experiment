#!/usr/bin/perl

# ---------------------------------------------------------------
# Copyright (C) 2022  Equinox Open Library Initiative, Inc.
# Galen Charlton <gmc@equinoxOLI.org>
# Mike Rylander <mrylander@gmail.com>

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# ---------------------------------------------------------------


# Add an nginx config block to the https section:
#
# location /openapi3 {
#     proxy_pass http://localhost:8080;
#     proxy_set_header Host $host;
#     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
#     proxy_set_header X-Forwarded-Proto $scheme;
#     proxy_read_timeout 300s;
# }
#
#
# And start it up like this:
#
# ./eg-api.pl daemon -m production -l http://localhost:8080

use strict;
use warnings;

use MIME::Base64;
use Scalar::Util qw/blessed/;
use Types::Serialiser;
use Mojolicious::Lite;
use OpenSRF::System;
use OpenSRF::AppSession;
use OpenSRF::Utils::SettingsClient;
use OpenILS::Utils::Fieldmapper;
use OpenILS::Application::AppUtils;
use OpenILS::Utils::CStoreEditor q/new_editor/;
use Data::Dumper;

#-------------------------------------------------
# globals and setup
my $U = "OpenILS::Application::AppUtils";

my $osrf_config = '/openils/conf/opensrf_core.xml';

OpenSRF::System->bootstrap_client(config_file => $osrf_config);

Fieldmapper->import(
    IDL => OpenSRF::Utils::SettingsClient->new->config_value("IDL")
);

OpenILS::Utils::CStoreEditor->init;

#-------------------------------------------------
# boilerplate

my $config = {
  openapi => "3.0.0",
  info => {
    description => "RESTful API for the Evergreen ILS",
    version => "0.2.0",
    title => "Evergreen API",
    license => {
      name => "GNU Public License 2.0+"
    }
  },
  servers => [
    { url => "/openapi3/v1" }
  ],
  tags => [
    { name => "self", description => "Access to library records on behalf of a patron" },
    { name => "holds", description => "Access to hold-related data" },
    { name => "circs", description => "Access to circ-related data" },
    { name => "bibs", description => "Access to bib oriented data" },
    { name => "items", description => "Access to item related data" },
    { name => "courses", description => "Access to course reserve related data" },
  ]
};

#-------------------------------------------------
# supported security schemes

$$config{components}{securitySchemes} = {
  basicAuth => { # /only/ used to get a token, handler does the actual auth and the plugin sub is just a passthrough
    type   => "http",
    scheme => "basic"
  },
  passthroughUser => { # /only/ used to get a token, handler does the actual auth and the plugin sub is just a passthrough
    type => "apiKey",
    in   => "query",
    name => "u"
  },
  passthroughPass => { # /only/ used to get a token, handler does the actual auth and the plugin sub is just a passthrough
    type => "apiKey",
    in   => "query",
    name => "p"
  },
  bearerAuth => {
    type   => "http",
    scheme => "bearer"
  },
  cookieAuth => {
    type => "apiKey",
    in   => "cookie",
    name => "eg.auth.token"
  },
  paramAuth => {
    type => "apiKey",
    in   => "query",
    name => "ses"
  }
};
 

#-------------------------------------------------
# schema definitions based on FM classes

$$config{components}{schemas} = generate_schemas();


#-------------------------------------------------
# OpenAPI defintions and MJ handlers, mapped to the same path and linked by operationId

add_path( '/self/auth',
  get => {
    security => [
      { basicAuth => ['OPAC_LOGIN', 'REST.api'] },
      { passthroughUser => ['OPAC_LOGIN', 'REST.api'],
        passthroughPass => ['OPAC_LOGIN', 'REST.api'] }
    ],
    tags => [ "self" ],
    summary => "Authenticate API user",
    operationId => "authenticateUser",
    parameters => [
      { name => u => in => query => schema => { type => 'string' } },
      { name => p => in => query => schema => { type => 'string' } }
    ],
    responses => {
      200 => {
        description => "successful authentication",
        content => {
          'application/json' => {
            schema => {
              type => "object"
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $u = $c->req->param('u');
    my $p = $c->req->param('p');

    my ($type, $creds) = split ' ', $c->req->headers->authorization;
    if ($creds and $type =~ /basic/i) {
        $creds = decode_base64($creds);
        ($u,$p) = split ':', $creds;
    }

    my $auth = $U->simplereq(
        'open-ils.auth', 'open-ils.auth.login',
        { identifier => $u,
          password => $p,
          type => 'opac'
        }
    );

    die 'login failed' unless ($auth->{textcode} eq 'SUCCESS');

    $c->render(openapi => { token => $auth->{payload}->{authtoken} });
  }
);

add_path('/self/me',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ "self" ],
    summary => "Retrieve patron profile",
    operationId => "retrieveSelfPatronProfile",
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              '$ref' => "#/components/schemas/au"
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');

    my $e = new_editor(authtoken => $ses);
    my $usr = $e->retrieve_actor_user([
        $user_obj->id,
        {flesh => 1, flesh_fields => {au => [qw/card cards addresses/]}}
    ]) or die "failed";

    $c->render(openapi => $usr->to_bare_hash(1));

  },

  patch => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ "self" ],
    summary => "Update one or more parts of the patron profile: password, email, username, locale; requires current_password patch property to validate all requests.",
    operationId => "selfUpdateParts",
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "object",
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');
    my $update_parts = $c->req->json;
    my $orig_pw = delete $$update_parts{current_password};

    my %results;
    for my $part ( keys %$update_parts ) {
        my $res = $U->simplereq(
            'open-ils.actor', "open-ils.actor.user.$part.update",
            $ses => $$update_parts{$part} => $orig_pw
        ) or die "user update call failed";
        if (ref($res)) {
            $results{$part} = { success => 0, error => $res };
        } else {
            $results{$part} = { success => 1 };
        }
    }

    $c->render( openapi => \%results );

  }
);

add_path('/self/holds',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ qw/self holds/ ],
    summary => "Retrieve patron holds",
    operationId => "retrieveSelfHolds",
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "array",
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');

    $c->render(openapi => to_bare_mixed_ref(
        $U->simplereq(
            'open-ils.circ',
            'open-ils.circ.hold.details.batch.retrieve.atomic',
            $ses,
            $U->simplereq(
                'open-ils.circ',
                'open-ils.circ.holds.id_list.retrieve',
                $ses
            )
        )
    ));
  },

  post => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ qw/self holds/ ],
    summary => "Request a bib or copy hold",
    operationId => "requestSelfHold",
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "object",
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');
    my $hold_parts = $c->req->json;

    die 'Invalid hold request' unless (ref($hold_parts) and ($$hold_parts{bib} or $$hold_parts{copy}));

    my $type = $$hold_parts{bib} ? 'T' : 'C';
    my $new_hold = {
        patronid  => $user_obj->id,
        hold_type => $type,
        pickup_lib => $$hold_parts{pickup_lib},
        expire_time => $$hold_parts{expire_time},
    };

    my $target = [ $$hold_parts{bib} || $$hold_parts{copy} ];
    my $result = $U->simplereq('open-ils.circ', 'open-ils.circ.holds.test_and_create.batch.override.atomic', $ses, $new_hold, $target)->[0];

    $$result{error} = ref($$result{result}) ? 1 : 0;

    $c->render(openapi => $result);

  }
);

add_path('/self/hold/:hold',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ qw/self holds/ ],
    summary => "Retrieve one hold",
    operationId => "retrieveSelfHold",
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "object"
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');
    my $holdid = $c->stash('hold');

    $c->render(openapi => to_bare_mixed_ref(
        $U->simplereq(
            'open-ils.circ',
            'open-ils.circ.hold.details.batch.retrieve.atomic',
            $ses,
            [$holdid]
        )->[0]
    ));
  },

  patch => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ qw/self holds/ ],
    summary => "Update one hold",
    operationId => "updateSelfHold",
    responses => {
      200 => {
        description => "successful update",
        content => {
          'application/json' => {
            schema => {
              type => "object"
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');
    my $holdid = $c->stash('hold');
    my $hold_patch = $c->req->json;

    $$hold_patch{id} = $holdid;
    my $res = $U->simplereq('open-ils.circ', 'open-ils.circ.hold.update', $ses, undef, $hold_patch);

    $res = { errors => 0 } if $res and !ref($res);
    $c->render(openapi => $res);

  },

  delete => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ qw/self holds/ ],
    summary => "Cancel one hold",
    operationId => "cancelSelfHold",
    responses => {
      200 => {
        description => "successful cancelation",
        content => {
          'application/json' => {
            schema => {
              type => "object"
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');
    my $holdid = $c->stash('hold');

    my $res = $U->simplereq('open-ils.circ', 'open-ils.circ.hold.cancel', $ses, $holdid, 6);

    $res = { errors => 0 } if $res and !ref($res);
    $c->render(openapi => $res);

  }
);

add_path('/self/transactions/:state',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ "self" ],
    summary => "Retrieve transaction lists; state is one of: all have_charge still_open have_balance have_bill have_bill_or_payment have_payment",
    operationId => "retrieveSelfXacts",
    parameters => [
      { name => sort => in => query => schema => { type => 'string' } },
      { name => limit => in => query => schema => { type => 'integer' } },
      { name => offset => in => query => schema => { type => 'integer' } }
    ],
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "array",
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $limit = $c->req->param('limit');
    my $offset = $c->req->param('offset') || 0;
    my $sort = $c->req->param('sort') || 'desc';

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');
    my $state = $c->stash('state');

    my $method = '';
    if ($state eq 'all') {
        $method = 'open-ils.actor.user.transactions.history.fleshed';
    } elsif (grep { $_ eq $state } qw/have_charge still_open have_balance have_bill have_bill_or_payment have_payment/) {
        $method = "open-ils.actor.user.transactions.history.$state.fleshed";
    }

    die 'Invalid transaction request' unless $method;

    my $xacts = $U->simplereq(
        'open-ils.actor', $method, $ses, $user_obj->id
    );

    $xacts = [ reverse(@$xacts) ] if $sort eq 'asc';
    $xacts = [ splice(@$xacts, $offset, $limit) ] if ($limit);

    $c->render(openapi => to_bare_mixed_ref($xacts));
  }
);

add_path('/self/transaction/:xact',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ "self" ],
    summary => "Retrieve transaction details",
    operationId => "retrieveSelfXact",
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "object"
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');
    my $xact = $c->stash('xact');

    die 'Invalid transaction request' unless $xact =~ /^\d+$/;

    $c->render(openapi => to_bare_mixed_ref(
        $U->simplereq(
            'open-ils.actor', 'open-ils.actor.user.transactions.history.fleshed',
            $ses, $user_obj->id, undef, { id => $xact }
        )->[0]
    ));
  }
);

add_path('/self/checkouts',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ "self" ],
    summary => "Retrieve current checkouts",
    operationId => "retrieveSelfCircs",
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "array",
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');

    $c->render(openapi => to_bare_mixed_ref(
        $U->simplereq(
            'open-ils.circ',
            'open-ils.circ.actor.user.checked_out.atomic',
            $ses, $user_obj->id
        )
    ));
  }
);

add_path('/self/checkouts/history',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ "self" ],
    summary => "Retrieve all checkouts",
    operationId => "retrieveSelfCircHistory",
    parameters => [
      { name => sort => in => query => schema => { type => 'string' } },
      { name => limit => in => query => schema => { type => 'integer' } },
      { name => offset => in => query => schema => { type => 'integer' } }
    ],
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "array",
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $limit = $c->req->param('limit');
    my $offset = $c->req->param('offset') || 0;
    my $sort = $c->req->param('sort');

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');

    my $xacts = $U->simplereq(
        'open-ils.actor',
        'open-ils.actor.user.transactions.history.fleshed',
        $ses, $user_obj->id, 'circulation'
    );

    $xacts = [ reverse(@$xacts) ] if $sort eq 'asc';
    $xacts = [ splice(@$xacts, $offset, $limit) ] if ($limit);

    $c->render(openapi => to_bare_mixed_ref($xacts));
  }
);

add_path('/self/checkout/:circ',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ "self" ],
    summary => "Retrieve a specific checkout",
    operationId => "retrieveSelfCirc",
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "object"
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');
    my $id = $c->stash('circ');

    my $e = new_editor(authtoken => $ses);
    my $circ = $e->retrieve_action_circulation([
        $id,
        {   flesh => 3,
            flesh_fields => {
                circ => ['target_copy'],
                acp => ['call_number'],
                acn => ['record']
            }
        }
    ]);

    die 'invalid circulation id' unless $circ and $circ->usr == $user_obj->id;

    # un-flesh for consistency
    my $cp = $circ->target_copy;
    $circ->target_copy($cp->id);

    my $cn = $cp->call_number;
    $cp->call_number($cn->id);

    my $t = $cn->record;
    $cn->record($t->id);

    $c->render(openapi => to_bare_mixed_ref(
        { circ   => $circ,
          copy   => $cp,
          record => $U->record_to_mvr($t)
        }
    ));
  },

  delete => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ "self" ],
    summary => "check in a specific checkout",
    operationId => "checkinSelfCirc",
    responses => {
      200 => {
        description => "successful checkin",
        content => {
          'application/json' => {
            schema => {
              type => "object"
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');
    my $id = $c->stash('circ');

    my $e = new_editor(authtoken => $ses);
    my $circ = $e->retrieve_action_circulation([
        $id,
        {flesh => 1, flesh_fields => { circ => ['target_copy'] }}
    ]);

    die 'invalid circulation id' unless $circ and $circ->usr == $user_obj->id;

    my $res = $U->simplereq(
        'open-ils.circ', 'open-ils.circ.checkin', $ses,
        { barcode => $circ->target_copy->barcode, force => 1, noop => 1 }
    );
    $res = [$res] if (ref($res) ne 'ARRAY');

    my $errors = [ grep { $$_{textcode} ne 'SUCCESS' } @$res ];
    my $resp = {
        errors => int(scalar(@$errors)),
        result => $res
    };

    $c->render(openapi => $resp);

  }
);

add_path('/self/checkout/:circ/renewal', # XXX: should this be a PUT or POST to /self/checkout/:circ?
  post => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ "self" ],
    summary => "Renew a specific checkout",
    operationId => "renewSelfCirc",
    responses => {
      200 => {
        description => "successful renewal",
        content => {
          'application/json' => {
            schema => {
              type => "object"
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');
    my $id = $c->stash('circ');

    my $e = new_editor(authtoken => $ses);
    my $circ = $e->retrieve_action_circulation($id);
    die 'invalid circulation id' unless $circ->usr == $user_obj->id;
    
    my $res = $U->simplereq(
        'open-ils.circ', 'open-ils.circ.renew', $ses,
        { copy_id => $circ->target_copy, patron_id => $user_obj->id}
    );
    $res = [$res] if (ref($res) ne 'ARRAY');

    my $errors = [ grep { $$_{textcode} ne 'SUCCESS' } @$res ];

    $c->render(openapi => to_bare_mixed_ref(
        { errors => int(scalar(@$errors)), result => $res }
    ));
  }
);

add_path( '/self/standing_penalties',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN']
        }} qw/bearer cookie param/
    ],
    tags => [ "self" ],
    summary => "Retrieve penalties (blocks)",
    operationId => "selfActivePenalties",
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => 'array',
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');

    my $e = new_editor(authtoken => $ses);
    $c->render(openapi => to_bare_mixed_ref(
        $e->search_actor_user_standing_penalty([
            {   usr => $user_obj->id,
                '-or' => [
                    {stop_date => undef},
                    {stop_date => {'>' => 'now'}}
                ]
            },
            {   flesh => 1,
                flesh_fields => {ausp => ['standing_penalty','usr_message']}
            }
        ])
    ));
  }
);

add_path('/bibs/:id/holdings',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN', 'REST.api,REST.api.bibs']
        }} qw/bearer cookie param/
    ],
    tags => [ "bibs" ],
    summary => "Call number and item 'tree' of holdings for a bib",
    operationId => "holdingsByBib",
    responses => {
      200 => {
        description => "List of call number objects containing item objects",
        content => {
          'application/json' => {
            schema => {
              type => 'array',
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    # Should this filter in some way for the user?

    my $bib = $c->stash('id');
    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');

    my $e = new_editor(authtoken => $ses);
    my $acn = $e->search_asset_call_number([
        {record => $bib, label => { '<>' => '##URI##'}, deleted => 'f'},
        {flesh => 2, flesh_fields => {acn => [qw/copies prefix suffix/], acp => [qw/status circ_lib location parts/]}}
    ]) or die "cn tree fetch failed";

    for my $cn (@{$acn}) {
        $cn->copies([
            grep {
                !$U->is_true($_->deleted)
                and $U->is_true($_->opac_visible)
                and $U->is_true($_->location->opac_visible)
                and $U->is_true($_->circ_lib->opac_visible)
            } @{$cn->copies}
        ]);
    }

    $acn = [ grep { @{$_->copies} > 0 } @$acn ];

    $c->render(openapi => to_bare_mixed_ref($acn));
  }
);

add_path('/bibs/:id/display_fields',
  [qw/get post/] => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN', 'REST.api,REST.api.bibs']
        }} qw/bearer cookie param/
    ],
    tags => [ "bibs" ],
    summary => "Display fields with optional highlighting",
    operationId => "bibDisplayFields",
    responses => {
      200 => {
        description => "Set of display field objects",
        content => {
          'application/json' => {
            schema => {
              type => 'array',
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $bib = $c->stash('id');
    my $map = $c->req->text || '""=>"-1"';

    $c->render(openapi => to_bare_mixed_ref(
        $U->simplereq(
            'open-ils.search',
            'open-ils.search.fetch.metabib.display_field.highlight',
            $map => $bib
        )
    ));
  }
);

add_path('/items/new',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN', 'REST.api,REST.api.items']
        }} qw/bearer cookie param/
    ],
    tags => [ "items" ],
    summary => "List of new items",
    operationId => "newItems",
    parameters => [
      { name => maxAge => in => query => schema => { type => 'string', format => 'interval' } },
      { name => limit => in => query => schema => { type => 'integer', default => 50 } },
      { name => offset => in => query => schema => { type => 'integer', default => 0 } }
    ],
    responses => {
      200 => {
        description => "List of call number objects containing item objects",
        content => {
          'application/json' => {
            schema => {
              type => 'array',
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');

    my $limit = $c->req->param('limit');
    my $offset = $c->req->param('offset') || 0;
    my $age = $c->req->param('maxAge');

    my $filter = {deleted => 'f', active_date => {'!=' => undef}};
    $$filter{active_date} = {
        '>=' => {
            transform => 'age',
            params => ['now'],
            value => '-' . $age
        }
    } if ($age);

    my $order = {order_by => {acp => 'active_date DESC'}};
    if ($limit) {
        $$order{limit} = $limit;
        $$order{offset} = $offset;
    }

    my $e = new_editor(authtoken => $ses);
    $c->render(openapi => to_bare_mixed_ref(
        $e->search_asset_copy([ $filter, $order ])
    ))
  }
);

add_path('/courses',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN', 'REST.api,REST.api.course_reserves']
        }} qw/bearer cookie param/
    ],
    tags => [ "courses" ],
    summary => "Retrieve course listing",
    operationId => 'activeCourses',
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "array",
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');

    my $e = new_editor(authtoken => $ses);
    $c->render(openapi => to_bare_mixed_ref(
        $e->search_asset_course_module_course([
            {is_archived => 'f'},
            {flesh => 1, flesh_fields => {acmc => [qw/owning_lib/]}}
        ])
    ));
  }
);

add_path('/course/:course/materials',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN', 'REST.api,REST.api.course_reserves']
        }} qw/bearer cookie param/
    ],
    tags => [ "courses" ],
    summary => "Retrieve course material listing",
    operationId => 'courseMaterials',
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "array",
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    my $c_id = $c->stash('course');

    $c->render(openapi => to_bare_mixed_ref(
        $U->simplereq(
            'open-ils.courses',
            'open-ils.courses.course_materials.retrieve.fleshed',
            { course => $c_id }
        )
    ));
  }
);

add_path('/course/:course/public_role_users',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN', 'REST.api,REST.api.course_reserves']
        }} qw/bearer cookie param/
    ],
    tags => [ "courses" ],
    summary => "Retrieve specific course public user listing",
    operationId => 'coursePublicRoleCourseUsers',
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "array",
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    $c->render(
        openapi => $U->simplereq(
            'open-ils.courses',
            'open-ils.courses.course_users.retrieve',
            $c->stash('course')
        )
    );

  }
);

add_path('/courses/public_role_users',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN', 'REST.api,REST.api.course_reserves']
        }} qw/bearer cookie param/
    ],
    tags => [ "courses" ],
    summary => "Retrieve course users with public role",
    operationId => 'publicRoleCourseUsers',
    responses => {
      200 => {
        description => "successful retrieval",
        content => {
          'application/json' => {
            schema => {
              type => "array",
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    $c->render(
        openapi => $U->simplereq(
            'open-ils.courses',
            'open-ils.courses.course_users.retrieve',
            { '!=' => undef }
        )
    );

  }
);

add_path('/holds/pickupLocations',
  get => {
    security => [
        map {{
            $_.'Auth' => ['OPAC_LOGIN', 'REST.api,REST.api.holds']
        }} qw/bearer cookie param/
    ],
    tags => [ "holds" ],
    summary => "List of org units that can be used as pickup locations",
    operationId => "pickupLibs",
    responses => {
      200 => {
        description => "List of objects with id, name, shortname keys",
        content => {
          'application/json' => {
            schema => {
              type => 'array',
              items => { type => 'object' }
            }
          }
        }
      }
    }
  } => sub {
    my $c = shift->openapi->valid_input or return;
    apply_locale($c);

    # Should this filter in some way for the user?

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');

    my $e = new_editor(authtoken => $ses);
    $c->render(openapi => to_bare_mixed_ref(
        $e->search_actor_org_unit({
            opac_visible => 't',
            ou_type      => $e->search_actor_org_unit_type(
                [{ can_have_vols => 't' }],
                { idlist => 1 }
            )
        })
    ));
  }
);


#-------------------------------------------------
# Finally, let the openapi plugin do it's thing

plugin OpenAPI => {
    url => $config,
    security => {
        basicAuth  => sub { return $_[3]->($_[0]) },
        bearerAuth => sub { return securityCheck(@_) },
        cookieAuth => sub { return securityCheck(@_) },
        paramAuth  => sub { return securityCheck(@_) }
    },
};

#-------------------------------------------------
# Ready to go...

app->start;


#-------------------------------------------------
# Support functions

sub add_path {
    my $path = shift;

    while (@_) {
        my $method = shift;
        my $def= shift;
        my $handler = shift;

        $method = [$method] unless ref $method;

        for my $m (@$method) {
            my $m_def = { %$def };
            $$m_def{operationId} .= "_$m";
            $$config{paths}{$path}{$m} = $m_def;
            $m = 'del' if ($m eq 'delete'); # for registration via del()

            &{\&{$m}}( # get, post, put, patch, del, etc, from MJ::L
                $path => $handler => $$m_def{operationId}
            );
        }
    }
}

sub securityCheck {
    my ($c, $defintion, $scopes, $cb) = @_;

    my $authz_header = $c->req->headers->authorization || '';
    my $ses = [split ' ', $authz_header]->[-1]
        || $c->cookie('eg.auth.token')
        || $c->req->param('ses');

    return $cb->($c,'no authtoken provided') unless $ses;

    $ses =~ s/\s+//;
    $ses =~ s/^%22//; $ses =~ s/%22$//;
    $ses =~ s/^['"]//; $ses =~ s/['"]$//;

    $scopes = ref($scopes) ? $scopes : [$scopes];

    my ($user_obj, $evt) = $U->checkses($ses);
    return $cb->($c,'invalid session') if ($evt);

    my $pass = 0;
    for my $s (@$scopes) {
        my $evt = $U->check_perms($user_obj->id, $user_obj->home_ou, split(',',$s));
        $pass++ unless $evt;
    }

    return $cb->($c,'permission denied') unless $pass;

    $c->stash(eg_auth_token => $ses);
    $c->stash(eg_user_obj => $user_obj);
    return $cb->($c);
}

sub generate_schemas {
    my %schemas;
    for my $c (Fieldmapper->classes) {
        my $h = $c->json_hint;
        my $required = $c->Identity;

        $schemas{$h} = {
            type       => 'object',
            properties => {},
        };

        for my $p ($c->properties) {
            my $info = $c->FieldInfo($p);

            my $real_type = $$info{primitive} || $$info{datatype} || '';
            my $type = $$info{datatype} || 'text';
            my $format;
            my $nullable = !$$info{required} ? Types::Serialiser::true : Types::Serialiser::false;

            #XXX Fixing some broken data
            $type = 'string' if ($real_type eq 'string' and $type eq 'float');

            if ($type eq 'timestamp') {
                ($type,$format) = (string => 'date-time');
            } elsif ($type eq 'id') {
                ($type,$format) = (string => 'identifier');
            } elsif ($type eq 'text') {
                ($type,$format) = (string => undef);
            } elsif ($type eq 'money') {
                ($type,$format) = (string => 'money');
            } elsif ($type eq 'bool') {
                ($type,$format) = (boolean => undef);
            } elsif ($type eq 'org_unit') {
                ($type,$format) = (link => undef);
            } elsif ($type eq 'int') {
                ($type,$format) = (integer => 'int64');
            } elsif ($type eq 'number' || $type eq 'float') {
                ($type,$format) = (number => 'float');
            } elsif ($type eq 'interval') {
                ($type,$format) = (string => 'interval');
            } elsif ($type ne 'link') {
                ($type,$format) = (string => undef);
            }

            my $ref;
            if ($type eq 'link' and my $link = $c->FieldLink($p)) {
                $ref = { oneOf => [ { format => $$link{class}, type => 'string', nullable => $nullable }, { '$ref' => "#/components/schemas/$$link{class}" } ] };
                $ref = $$link{reltype} eq 'has_many' ?  { nullable => $nullable, type => array => items => $ref } : $ref;
            } else {
                $type = 'string' if $type eq 'link'; # fallback
                $ref = { nullable => $nullable, type => $type };
                $$ref{format} = $format if ($format);
            }

            $schemas{$h}{properties}{$p} = $ref
        }
    }
    return \%schemas;
}

sub apply_locale {
    OpenSRF::AppSession->reset_locale;
    OpenSRF::AppSession->default_locale(
        parse_eg_locale(
            parse_accept_lang($_[0]->req->headers->accept_language) || 'en_us'
        )
    );
}

sub parse_accept_lang {
    my $al = shift;
    return undef unless $al;
    my ($locale) = split(/,/, $al);
    ($locale) = split(/;/, $locale);
    return undef unless $locale;
    $locale =~ s/-/_/og;
    return $locale;
}

# Accept-Language uses locales like 'en', 'fr', 'fr_fr', while Evergreen
# internally uses 'en-US', 'fr-CA', 'fr-FR' (always with the 2 lowercase,
# hyphen, 2 uppercase convention)
sub parse_eg_locale {
    my $ua_locale = shift || 'en_us';

    $ua_locale =~ m/^(..).?(..)?$/;
    my $lang_code = lc($1);
    my $region_code = $2 ? uc($2) : uc($1);
    return "$lang_code-$region_code";
}

sub to_bare_mixed_ref {
    my $thing = shift;
    my $thing_type = ref($thing);
    return $thing unless $thing_type;

    return $thing->to_bare_hash(1)
        if (blessed($thing) and $thing->isa('Fieldmapper'));

    if ($thing_type eq 'HASH') {
        return { map { ($_, to_bare_mixed_ref($$thing{$_})) } keys %$thing };
    } elsif ($thing_type eq 'ARRAY') {
        return [ map { to_bare_mixed_ref($_) } @$thing ];
    }

    # dunno what to do with it...
    return $thing;
}

package Fieldmapper;

# rewriting these with deep-recursion verions
sub to_bare_hash {
    my $self = shift;
    my $deep = shift;
    my $cname = $self->class_name;

    my %hash = ();
    for my $f ($self->properties) {
        my $val = $self->$f;
        my $vtype = $cname->FieldDatatype($f) || '';
        if ($deep
            and ref($val)
            and exists $$fieldmap{$cname}{links}{$f}
        ) {
            my $fclass = Fieldmapper::class_for_hint($$fieldmap{$cname}{links}{$f}{class});
            if ($fclass and $$fieldmap{$cname}{links}{$f}{reltype} eq 'has_many' and @$val) {
                $val = [ map { (blessed($_) and $_->isa('Fieldmapper')) ? $_->to_bare_hash($deep) : $_ } @$val ];
            } elsif (blessed($val) and $val->isa('Fieldmapper')) {
                $val = $val->to_bare_hash($deep);
            }
        } elsif (defined($val) and $vtype eq 'bool') {
            $val = $U->is_true($val) ? Types::Serialiser::true : Types::Serialiser::false;
        } elsif (
            $val
            and $vtype eq 'timestamp'
            and $val =~ /^(\S{10}T\S{8}[-+]\d{2})(\d{2})$/
        ) {
                $val = "$1:$2";
        } elsif (
            $val
            and $vtype eq 'timestamp'
            and $val =~ /^\S{10}$/
        ) {
                $val .= 'T00:00:00Z';
        }
        $hash{$f} = $val;
    }

    return \%hash;
}

sub from_bare_hash {
    my $self = shift;
    my $hash = shift;
    my $deep = shift;
    my $cname = $self->class_name;

    my @value = ();
    for my $f ($self->properties) {
        my $val = $$hash{$f};
        if ($deep
            and ref($val)
            and $self->FieldDatatype($f) eq 'link'
        ) {
            my $fclass = Fieldmapper::class_for_hint($$fieldmap{$cname}{links}{$f}{class});
            if ($fclass and $$fieldmap{$cname}{links}{$f}{reltype} eq 'has_many' and @$val) {
                $val = [ map { $fclass->from_bare_hash($_, $deep) } @$val ];
            } elsif (blessed($val)) {
                $val = $fclass->from_bare_hash($val, $deep);
            }
        }
        push @value, $val;
    }
    return $self->new(\@value);
}

sub FieldLink {
    my $self = shift;
    my $f = shift;
    return undef unless ($f && exists $$fieldmap{$self->class_name}{links}{$f});
    return $$fieldmap{$self->class_name}{links}{$f};
}

