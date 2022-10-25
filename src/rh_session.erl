-module(realhero_session).

-behavior(oauth2_backend).

%%gen_server API
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%%% API
-export([add_client/4,
        add_user/2,
        add_user/3,
        delete_client/1,
        delete_user/1
       ]).

%%% OAuth2 backend functionality
-export([authenticate_user/2,
        authenticate_client/2,
        associate_access_code/3,
        associate_access_token/3,
        associate_refresh_token/3,
        resolve_access_code/2,
        resolve_access_token/2,
        resolve_refresh_token/2,
        revoke_access_code/2,
        revoke_access_token/2,
        revoke_refresh_token/2,
        get_client_identity/2,
        get_redirection_uri/2,
        verify_redirection_uri/3,
        verify_client_scope/3,
        verify_resowner_scope/3,
        verify_scope/3
       ]).

%% API
-http_api({"token", login, [{"username", binary},
                           {"password", binary},
                           {"client_id",binary},
                           {"client_secret",binary},
                           {"scope",binary}]}).

-define(DEFAULT_REALM,{<<"RealHero">>,<<"Academy">>}).

-record(client, {client_id :: binary(), client_secret :: binary(), redirect_uri :: binary(), scope :: [binary()]}).
-record(user, {username :: binary(), password :: binary(), scope :: scope()}).

-type scope()    :: oauth2:scope().

login(Username, Password, <<"default_realm">>, <<"no_secret">>, Scope) ->
  {Client_Id,Client_Secret} = ?DEFAULT_REALM,
  login(Username, Password, Client_Id, Client_Secret, Scope);

login(Username, Password, Client_Id, Client_Secret, Scope) ->
  case oauth2:authorize_password({Username,Password},{Client_Id,Client_Secret},Scope,[]) of
    {ok,{Ctx0,A}} -> case oauth2:issue_token_and_refresh(A,Ctx0) of
                      {ok,{Ctx1,Response}} ->
                        {ok, AccessToken} = oauth2_response:access_token(Response),
                        {ok, ExpiresIn} = oauth2_response:expires_in(Response),
                        {ok, ResOwner} = oauth2_response:resource_owner(Response),
                        {ok, ScopeOut} = oauth2_response:scope(Response),
                        {ok, RefreshToken} = oauth2_response:refresh_token(Response),
                        {ok, RExpiresIn} = oauth2_response:refresh_token_expires_in(Response),



                        {ok,{token,[{access_token, AccessToken},
                                    {expires_in, ExpiresIn},
                                    {resource_owner, ResOwner#user{password=hidden}},
                                    {scope, ScopeOut},
                                    {refresh_token, RefreshToken},
                                    {refresh_token_expires_in, RExpiresIn}
                                 ]}};
                      E -> E
                    end;
    E -> E
  end.


-spec add_client(Id, Secret, RedirectURI, Scope) -> ok when
   Id          :: binary(),
   Secret      :: binary() | undefined,
   RedirectURI :: binary(),
   Scope       :: [binary()].
add_client(Id, Secret, RedirectURI, Scope) ->
   put(clients, Id, #client{client_id = Id,
                                  client_secret = Secret,
                                  redirect_uri = RedirectURI,
                                  scope = Scope
                                 }),
   ok.
-spec delete_client(Id) -> ok when Id :: binary().
delete_client(Id) -> delete(clients, Id).

-spec add_user(Username, Password) -> ok when
   Username :: binary(),
   Password :: binary().
add_user(Username, Password) ->
   add_user(Username, Password, []),
   ok.

-spec add_user(Username, Password, Scope) -> ok when
   Username  :: binary(),
   Password  :: binary(),
   Scope     :: [binary()].
add_user(Username, Password, Scope) ->
   put(users, Username, #user{username = Username,
                                        password = hash(Password), scope = Scope}),
   ok.
-spec delete_user(Username) -> ok when Username :: binary().
delete_user(Username) -> delete(users, Username).

%%--------------------------------------------------------------------
%% gen_server callbacks
%%--------------------------------------------------------------------
-define(AUTH_TABLES,[access_codes, access_tokens, refresh_tokens, users, clients]).

init([]) ->
  lists:foreach(fun(Table) ->
                    ets:new(Table, [named_table, public])
                end, ?AUTH_TABLES),
  {ok, state}.

handle_call(_Req, _From, State) ->
    {reply, error,  State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Msg, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
  lists:foreach(fun ets:delete/1, ?AUTH_TABLES),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.



%%%===================================================================
%%% OAuth2 backend functions
%%%===================================================================

authenticate_user({Username, Password}, AppContext) ->
    case get(users, Username) of
        {ok, #user{password = <<Salt:4/binary, Hash/binary>>} = Identity} ->
          case Hash =:= md5_hash(Salt, Password) of
            false -> {error, access_denied};
            _ -> {ok, {AppContext, Identity}}
          end;
        {ok, #user{password = _WrongPassword}} ->
            {error, access_denied};
        _ ->
            {error, access_denied}
    end.

authenticate_client({ClientId, ClientSecret}, AppContext) ->
    case get(clients, ClientId) of
        {ok, #client{client_secret = ClientSecret} = Identity} ->
            {ok, {AppContext, Identity}};
        {ok, #client{client_secret = _WrongSecret}} ->
            {error, access_denied};
        _ ->
            {error, access_denied}
    end.

associate_access_code(AccessCode, Context, AppContext) ->
    put(access_codes, AccessCode, Context),
    {ok, AppContext}.

associate_access_token(AccessToken, Context, AppContext) ->
    put(access_tokens, AccessToken, Context),
    {ok, AppContext}.

associate_refresh_token(RefreshToken, Context, AppContext) ->
    put(refresh_tokens, RefreshToken, Context),
    {ok, AppContext}.

resolve_access_code(AccessCode, AppContext) ->
    case get(access_codes, AccessCode) of
        {ok, Grant} ->
            {ok, {AppContext, Grant}};
        Error = {error, notfound} ->
            Error
    end.

resolve_access_token(AccessToken, AppContext) ->
    case get(access_tokens, AccessToken) of
        {ok, Grant} ->
            {ok, {AppContext, Grant}};
        Error = {error, notfound} ->
            Error
    end.

resolve_refresh_token(RefreshToken, AppContext) ->
    case get(refresh_tokens, RefreshToken) of
        {ok, Grant} ->
            {ok, {AppContext, Grant}};
        Error = {error, notfound} ->
            Error
    end.

%% @doc Revokes an access code AccessCode, so that it cannot be used again.
revoke_access_code(AccessCode, AppContext) ->
    delete(access_codes, AccessCode),
    {ok, AppContext}.

%% Not implemented yet.
revoke_access_token(_AccessToken, _AppContext) ->
    {error, notfound}.

%% Not implemented yet.
revoke_refresh_token(_RefreshToken, _AppContext) ->
    {error, notfound}.

get_redirection_uri(ClientId, AppContext) ->
    case get(clients, ClientId) of
        {ok, #client{redirect_uri = RedirectUri}} ->
            {ok, {AppContext, RedirectUri}};
        {error, notfound} ->
            {error, notfound}
    end.

get_client_identity(ClientId, AppContext) ->
    case get(clients, ClientId) of
        {ok, Identity} ->
            {ok, {AppContext, Identity}};
        {error, notfound} ->
            {error, notfound}
    end.

verify_redirection_uri(#client{redirect_uri = _RegisteredUri}, undefined,
                       AppContext) ->
    {ok, AppContext};
verify_redirection_uri(#client{redirect_uri = _RegisteredUri}, <<>>,
                       AppContext) ->
    {ok, AppContext};
verify_redirection_uri(#client{redirect_uri = <<>>}, _Uri,
                       _AppContext) ->
    {error, baduri};
verify_redirection_uri(#client{redirect_uri = RegisteredUri}, RegisteredUri,
                       AppContext) ->
    {ok, AppContext};
verify_redirection_uri(#client{redirect_uri = _RegisteredUri}, _DifferentUri,
                       _AppContext) ->
    {error, baduri}.

verify_client_scope(#client{scope = RegisteredScope}, Scope, AppContext) ->
    verify_scope(RegisteredScope, Scope, AppContext).

verify_resowner_scope(#user{scope = RegisteredScope}, Scope, AppContext) ->
    verify_scope(RegisteredScope, Scope, AppContext).

verify_scope(RegisteredScope, undefined, AppContext) ->
    {ok, {AppContext, RegisteredScope}};
verify_scope(_RegisteredScope, [], AppContext) ->
    {ok, {AppContext, []}};
verify_scope([], _Scope, _AppContext) ->
    {error, invalid_scope};
verify_scope(RegisteredScope, Scope, AppContext) ->
    case oauth2_priv_set:is_subset(oauth2_priv_set:new(Scope),
                                   oauth2_priv_set:new(RegisteredScope)) of
        true ->
            {ok, {AppContext, Scope}};
        false ->
            {error, badscope}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

get(Table, Key) ->
    case ets:lookup(Table, Key) of
        [] ->
            {error, notfound};
        [{_Key, Value}] ->
            {ok, Value}
    end.

put(Table, Key, Value) ->
    ets:insert(Table, {Key, Value}).

delete(Table, Key) ->
    ets:delete(Table, Key).

hash(Password) ->
    SaltBin = salt(),
    <<SaltBin/binary, (md5_hash(SaltBin, Password))/binary>>.

md5_hash(SaltBin, Password) ->
    erlang:md5(<<SaltBin/binary, Password/binary>>).

salt() ->
    emqttd_time:seed(),
    Salt = rand:uniform(16#ffffffff),
    <<Salt:32>>.

code(ok)              -> [{status, success}];
code({error, Reason}) -> [{status, failure}, {reason, list_to_binary(Reason)}].
