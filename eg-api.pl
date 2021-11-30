#!/usr/bin/perl

# ---------------------------------------------------------------
# Copyright (C) 2021  Equinox Open Library Initiative, Inc.
# Galen Charlton <gmc@equinoxOLI.org>

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# ---------------------------------------------------------------


# proof of concept OpenAPI server for Evergreen
# start it up like this:
#
# ./eg-api.pl daemon -m production -l http://*:8080

use strict;
use warnings;

use Mojolicious::Lite;
use OpenSRF::System;
use OpenSRF::AppSession;
use OpenSRF::Utils::SettingsClient;
use OpenILS::Utils::Fieldmapper;
use OpenILS::Application::AppUtils;
use OpenILS::Utils::CStoreEditor q/new_editor/;
use Data::Dumper;

my $U = "OpenILS::Application::AppUtils";

get "/self" => sub {

    my $c = shift->openapi->valid_input or return;

    my $ses = $c->stash('eg_auth_token');
    my $user_obj = $c->stash('eg_user_obj');

    my $e = new_editor(authtoken => $ses);
    my $usr = $e->retrieve_actor_user($user_obj->id) or die "failed";

    my $resp = {
        usrname => $usr->usrname,
        first_given_name => $usr->first_given_name,
        family_name => $usr->family_name
    };

    $c->render(openapi => $resp);

}, "retrievePatronProfile";

plugin OpenAPI => {
    url => './openapi.json',
    security => {
        cookieAuth => sub {
            my ($c, $definition, $scopes, $cb) = @_;
            my $ses = $c->cookie('eg.auth.token');
            $ses =~ s/^%22//;
            $ses =~ s/%22$//;
            my ($user_obj, $evt) = $U->checkses($ses);
            if ($evt) {
                return $c->$cb('invalid session');
            } else {
                $c->stash(eg_auth_token => $ses);
                $c->stash(eg_user_obj => $user_obj);
                return $c->$cb();
            }
        }
    },
};

# startup
my $osrf_config = '/openils/conf/opensrf_core.xml';
OpenSRF::System->bootstrap_client(config_file => $osrf_config);
Fieldmapper->import(
    IDL => OpenSRF::Utils::SettingsClient->new->config_value("IDL"));
OpenILS::Utils::CStoreEditor->init;

app->start;
