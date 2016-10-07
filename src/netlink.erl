%% Copyright 2010-2013, Travelping GmbH <info@travelping.com>

%% Permission is hereby granted, free of charge, to any person obtaining a
%% copy of this software and associated documentation files (the "Software"),
%% to deal in the Software without restriction, including without limitation
%% the rights to use, copy, modify, merge, publish, distribute, sublicense,
%% and/or sell copies of the Software, and to permit persons to whom the
%% Software is furnished to do so, subject to the following conditions:

%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.

%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
%% FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
%% DEALINGS IN THE SOFTWARE.

-module(netlink).
-behaviour(gen_server).
-define(NETLINK_SERVER, 1).

-compile(inline).
-compile(inline_list_funcs).

-export([start/0, start/2, start/3,
	 start_link/0, start_link/2, start_link/3,
	 stop/0, stop/1]).

-export([subscribe/2, subscribe/3,
	 send/2, send/3,
	 request/2, request/3]).

-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2, code_change/3]).

-export([nl_ct_dec/1, nl_rt_dec/1,
	 nl_rt_enc/1, nl_ct_enc/1,
	 nl_dec/2, nl_enc/2,
	 linkinfo_enc/3, linkinfo_dec/3,
	 rtnl_wilddump/2]).
-export([sockaddr_nl/3, setsockopt/4]).
-export([rcvbufsiz/2]).
-export([notify/3]).

-export([nft_decode/2, nft_encode/2]).

-include_lib("gen_socket/include/gen_socket.hrl").
-include("netlink.hrl").
-include("netlink_codec.erl").

-define(SERVER, ?MODULE).
-define(TAB, ?MODULE).

-record(subscription, {
    pid                 :: pid(),
    types               :: [ct | rt | s]
}).

-record(state, {
    subscribers = []    :: [#subscription{}],
    ct                  :: gen_socket:socket(),
    rt                  :: gen_socket:socket(),

    msgbuf = []         :: [netlink_record()],
    curseq = 16#FF      :: non_neg_integer(),
    requests            :: gb_trees:tree()
}).

%%
%% grep define src/netlink.erl | awk -F"[(,]" '{ printf "enc_opt(%s)%*s ?%s;\n", tolower($2), 32 - length($2), "->", $2 }'
%%
enc_opt(netlink_route)                 -> ?NETLINK_ROUTE;
enc_opt(netlink_unused)                -> ?NETLINK_UNUSED;
enc_opt(netlink_usersock)              -> ?NETLINK_USERSOCK;
enc_opt(netlink_firewall)              -> ?NETLINK_FIREWALL;
enc_opt(netlink_inet_diag)             -> ?NETLINK_INET_DIAG;
enc_opt(netlink_nflog)                 -> ?NETLINK_NFLOG;
enc_opt(netlink_xfrm)                  -> ?NETLINK_XFRM;
enc_opt(netlink_selinux)               -> ?NETLINK_SELINUX;
enc_opt(netlink_iscsi)                 -> ?NETLINK_ISCSI;
enc_opt(netlink_audit)                 -> ?NETLINK_AUDIT;
enc_opt(netlink_fib_lookup)            -> ?NETLINK_FIB_LOOKUP;
enc_opt(netlink_connector)             -> ?NETLINK_CONNECTOR;
enc_opt(netlink_netfilter)             -> ?NETLINK_NETFILTER;
enc_opt(netlink_ip6_fw)                -> ?NETLINK_IP6_FW;
enc_opt(netlink_dnrtmsg)               -> ?NETLINK_DNRTMSG;
enc_opt(netlink_kobject_uevent)        -> ?NETLINK_KOBJECT_UEVENT;
enc_opt(netlink_generic)               -> ?NETLINK_GENERIC;
enc_opt(netlink_scsitransport)         -> ?NETLINK_SCSITRANSPORT;
enc_opt(netlink_ecryptfs)              -> ?NETLINK_ECRYPTFS;
enc_opt(netlink_add_membership)        -> ?NETLINK_ADD_MEMBERSHIP;
enc_opt(netlink_drop_membership)       -> ?NETLINK_DROP_MEMBERSHIP;
enc_opt(netlink_pktinfo)               -> ?NETLINK_PKTINFO;
enc_opt(netlink_broadcast_error)       -> ?NETLINK_BROADCAST_ERROR;
enc_opt(netlink_no_enobufs)            -> ?NETLINK_NO_ENOBUFS;
enc_opt(sol_netlink)                   -> ?SOL_NETLINK;
enc_opt(nfnlgrp_none)                  -> ?NFNLGRP_NONE;
enc_opt(nfnlgrp_conntrack_new)         -> ?NFNLGRP_CONNTRACK_NEW;
enc_opt(nfnlgrp_conntrack_update)      -> ?NFNLGRP_CONNTRACK_UPDATE;
enc_opt(nfnlgrp_conntrack_destroy)     -> ?NFNLGRP_CONNTRACK_DESTROY;
enc_opt(nfnlgrp_conntrack_exp_new)     -> ?NFNLGRP_CONNTRACK_EXP_NEW;
enc_opt(nfnlgrp_conntrack_exp_update)  -> ?NFNLGRP_CONNTRACK_EXP_UPDATE;
enc_opt(nfnlgrp_conntrack_exp_destroy) -> ?NFNLGRP_CONNTRACK_EXP_DESTROY;
enc_opt(rtnlgrp_none)                  -> ?RTNLGRP_NONE;
enc_opt(rtnlgrp_link)                  -> ?RTNLGRP_LINK;
enc_opt(rtnlgrp_notify)                -> ?RTNLGRP_NOTIFY;
enc_opt(rtnlgrp_neigh)                 -> ?RTNLGRP_NEIGH;
enc_opt(rtnlgrp_tc)                    -> ?RTNLGRP_TC;
enc_opt(rtnlgrp_ipv4_ifaddr)           -> ?RTNLGRP_IPV4_IFADDR;
enc_opt(rtnlgrp_ipv4_mroute)           -> ?RTNLGRP_IPV4_MROUTE;
enc_opt(rtnlgrp_ipv4_route)            -> ?RTNLGRP_IPV4_ROUTE;
enc_opt(rtnlgrp_ipv4_rule)             -> ?RTNLGRP_IPV4_RULE;
enc_opt(rtnlgrp_ipv6_ifaddr)           -> ?RTNLGRP_IPV6_IFADDR;
enc_opt(rtnlgrp_ipv6_mroute)           -> ?RTNLGRP_IPV6_MROUTE;
enc_opt(rtnlgrp_ipv6_route)            -> ?RTNLGRP_IPV6_ROUTE;
enc_opt(rtnlgrp_ipv6_ifinfo)           -> ?RTNLGRP_IPV6_IFINFO;
enc_opt(rtnlgrp_decnet_ifaddr)         -> ?RTNLGRP_DECnet_IFADDR;
enc_opt(rtnlgrp_nop2)                  -> ?RTNLGRP_NOP2;
enc_opt(rtnlgrp_decnet_route)          -> ?RTNLGRP_DECnet_ROUTE;
enc_opt(rtnlgrp_decnet_rule)           -> ?RTNLGRP_DECnet_RULE;
enc_opt(rtnlgrp_nop4)                  -> ?RTNLGRP_NOP4;
enc_opt(rtnlgrp_ipv6_prefix)           -> ?RTNLGRP_IPV6_PREFIX;
enc_opt(rtnlgrp_ipv6_rule)             -> ?RTNLGRP_IPV6_RULE;
enc_opt(rtnlgrp_nd_useropt)            -> ?RTNLGRP_ND_USEROPT;
enc_opt(rtnlgrp_phonet_ifaddr)         -> ?RTNLGRP_PHONET_IFADDR;
enc_opt(rtnlgrp_phonet_route)          -> ?RTNLGRP_PHONET_ROUTE.

%%
%% grep define src/netlink.erl | awk -F"[(,]" '{ printf "dec_opt(?%s)%*s %s;\n", $2, 32 - length($2), "->", tolower($2) }'
%%
%% dec_opt(?NETLINK_ROUTE)                 -> netlink_route;
%% dec_opt(?NETLINK_UNUSED)                -> netlink_unused;
%% dec_opt(?NETLINK_USERSOCK)              -> netlink_usersock;
%% dec_opt(?NETLINK_FIREWALL)              -> netlink_firewall;
%% dec_opt(?NETLINK_INET_DIAG)             -> netlink_inet_diag;
%% dec_opt(?NETLINK_NFLOG)                 -> netlink_nflog;
%% dec_opt(?NETLINK_XFRM)                  -> netlink_xfrm;
%% dec_opt(?NETLINK_SELINUX)               -> netlink_selinux;
%% dec_opt(?NETLINK_ISCSI)                 -> netlink_iscsi;
%% dec_opt(?NETLINK_AUDIT)                 -> netlink_audit;
%% dec_opt(?NETLINK_FIB_LOOKUP)            -> netlink_fib_lookup;
%% dec_opt(?NETLINK_CONNECTOR)             -> netlink_connector;
%% dec_opt(?NETLINK_NETFILTER)             -> netlink_netfilter;
%% dec_opt(?NETLINK_IP6_FW)                -> netlink_ip6_fw;
%% dec_opt(?NETLINK_DNRTMSG)               -> netlink_dnrtmsg;
%% dec_opt(?NETLINK_KOBJECT_UEVENT)        -> netlink_kobject_uevent;
%% dec_opt(?NETLINK_GENERIC)               -> netlink_generic;
%% dec_opt(?NETLINK_SCSITRANSPORT)         -> netlink_scsitransport;
%% dec_opt(?NETLINK_ECRYPTFS)              -> netlink_ecryptfs;
%% dec_opt(?NETLINK_ADD_MEMBERSHIP)        -> netlink_add_membership;
%% dec_opt(?NETLINK_DROP_MEMBERSHIP)       -> netlink_drop_membership;
%% dec_opt(?NETLINK_PKTINFO)               -> netlink_pktinfo;
%% dec_opt(?NETLINK_BROADCAST_ERROR)       -> netlink_broadcast_error;
%% dec_opt(?NETLINK_NO_ENOBUFS)            -> netlink_no_enobufs;
%% dec_opt(?SOL_NETLINK)                   -> sol_netlink;
%% dec_opt(?NFNLGRP_NONE)                  -> nfnlgrp_none;
%% dec_opt(?NFNLGRP_CONNTRACK_NEW)         -> nfnlgrp_conntrack_new;
%% dec_opt(?NFNLGRP_CONNTRACK_UPDATE)      -> nfnlgrp_conntrack_update;
%% dec_opt(?NFNLGRP_CONNTRACK_DESTROY)     -> nfnlgrp_conntrack_destroy;
%% dec_opt(?NFNLGRP_CONNTRACK_EXP_NEW)     -> nfnlgrp_conntrack_exp_new;
%% dec_opt(?NFNLGRP_CONNTRACK_EXP_UPDATE)  -> nfnlgrp_conntrack_exp_update;
%% dec_opt(?NFNLGRP_CONNTRACK_EXP_DESTROY) -> nfnlgrp_conntrack_exp_destroy.

setsockopt(Socket, Level, OptName, Val) when is_atom(Level) ->
    setsockopt(Socket, enc_opt(Level), OptName, Val);
setsockopt(Socket, Level, OptName, Val) when is_atom(OptName) ->
    setsockopt(Socket, Level, enc_opt(OptName), Val);
setsockopt(Socket, Level, OptName, Val) when is_atom(Val) ->
    setsockopt(Socket, Level, OptName, enc_opt(Val));
setsockopt(Socket, Level, OptName, Val) when is_integer(Val) ->
    gen_socket:setsockopt(Socket, Level, OptName, Val).

rcvbufsiz(Socket, BufSiz) ->
    case gen_socket:setsockopt(Socket, sol_socket, rcvbufforce, BufSiz) of
	ok -> ok;
	_ -> gen_socket:setsockopt(Socket, sol_socket, rcvbuf, BufSiz)
    end.

sockaddr_nl(Family, Pid, Groups) ->
    sockaddr_nl({Family, Pid, Groups}).

-spec sockaddr_nl({atom()|integer(),integer(),integer()}) -> binary();
    (binary())                               -> {atom()|integer(),integer(),integer()}.
sockaddr_nl({Family, Pid, Groups}) when is_atom(Family) ->
    sockaddr_nl({family(Family), Pid, Groups});
sockaddr_nl({Family, Pid, Groups}) ->
    << Family:16/native-integer, 0:16, Pid:32/native-integer, Groups:32/native-integer >>;
sockaddr_nl(<< Family:16/native-integer, _Pad:16, Pid:32/native-integer, Groups:32/native-integer >>) ->
    {family(Family), Pid, Groups}.

%%
%% API implementation
%%

start() ->
    start({local, ?SERVER}, [], []).

start(Args, Options) ->
    gen_server:start(?MODULE, Args, Options).

start(ServerName, Args, Options) ->
    gen_server:start(ServerName, ?MODULE, Args, Options).

start_link() ->
    start_link({local, ?SERVER}, [], []).

start_link(Args, Options) ->
    gen_server:start_link(?MODULE, Args, Options).

start_link(ServerName, Args, Options) ->
    gen_server:start_link(ServerName, ?MODULE, Args, Options).

stop() ->
    stop(?SERVER).

stop(ServerName) ->
    gen_server:cast(ServerName, stop).

-spec send(atom(), binary()) -> ok.
send(SubSys, Msg) ->
    send(?SERVER, SubSys, Msg).

-spec send(atom() | pid(), atom(), binary()) -> ok.
send(ServerName, SubSys, Msg) ->
    gen_server:cast(ServerName, {send, SubSys, Msg}).

subscribe(Pid, Types) ->
    subscribe(?SERVER, Pid, Types).

subscribe(ServerName, Pid, Types) ->
    gen_server:call(ServerName, {subscribe, #subscription{pid = Pid, types = Types}}).

-spec request(atom(), netlink_record()) -> {ok, [netlink_record(), ...]} | {error, term()}.
request(SubSys, Msg) ->
    request(?SERVER, SubSys, Msg).

-spec request(atom() | pid(), atom(), netlink_record()) -> {ok, [netlink_record(), ...]} | {error, term()}.
request(ServerName, SubSys, Msg) ->
    gen_server:call(ServerName, {request, SubSys, Msg}).

%%
%% gen_server callbacks
%%

init(Opts) ->
    {ok, CtNl} = socket(netlink, raw, ?NETLINK_NETFILTER, Opts),
    ok = gen_socket:bind(CtNl, sockaddr_nl(netlink, 0, -1)),
    ok = gen_socket:input_event(CtNl, true),

    ok = gen_socket:setsockopt(CtNl, sol_socket, sndbuf, 32768),
    ok = rcvbufsiz(CtNl, 128 * 1024),

    ok = setsockopt(CtNl, sol_netlink, netlink_add_membership, nfnlgrp_conntrack_new),
    ok = setsockopt(CtNl, sol_netlink, netlink_add_membership, nfnlgrp_conntrack_update),
    ok = setsockopt(CtNl, sol_netlink, netlink_add_membership, nfnlgrp_conntrack_destroy),
    ok = setsockopt(CtNl, sol_netlink, netlink_add_membership, nfnlgrp_conntrack_exp_new),
    ok = setsockopt(CtNl, sol_netlink, netlink_add_membership, nfnlgrp_conntrack_exp_update),
    ok = setsockopt(CtNl, sol_netlink, netlink_add_membership, nfnlgrp_conntrack_exp_destroy),

    {ok, RtNl} = socket(netlink, raw, ?NETLINK_ROUTE, Opts),
    ok = gen_socket:bind(RtNl, sockaddr_nl(netlink, 0, -1)),
    ok = gen_socket:input_event(RtNl, true),

    ok = gen_socket:setsockopt(RtNl, sol_socket, sndbuf, 32768),
    ok = rcvbufsiz(RtNl, 128 * 1024),

    ok = setsockopt(RtNl, sol_netlink, netlink_add_membership, rtnlgrp_link),
    ok = setsockopt(RtNl, sol_netlink, netlink_add_membership, rtnlgrp_notify),
    ok = setsockopt(RtNl, sol_netlink, netlink_add_membership, rtnlgrp_neigh),
    ok = setsockopt(RtNl, sol_netlink, netlink_add_membership, rtnlgrp_ipv4_ifaddr),
    ok = setsockopt(RtNl, sol_netlink, netlink_add_membership, rtnlgrp_ipv4_route),
    ok = setsockopt(RtNl, sol_netlink, netlink_add_membership, rtnlgrp_ipv6_ifaddr),
    ok = setsockopt(RtNl, sol_netlink, netlink_add_membership, rtnlgrp_ipv6_route),

    {ok, #state{
        ct = CtNl, rt = RtNl,
        requests = gb_trees:empty()
    }}.

handle_call({subscribe, #subscription{pid = Pid} = Subscription}, _From, #state{subscribers = Sub} = State) ->
    case lists:keymember(Pid, #subscription.pid, Sub) of
        true ->
            NewSub = lists:keyreplace(Pid, #subscription.pid, Sub, Subscription),
            {reply, ok, State#state{subscribers = NewSub}};
        false ->
            lager:debug("~p:Subscribe ~p~n", [?MODULE, Pid]),
            monitor(process, Pid),
            {reply, ok, State#state{subscribers = [Subscription|Sub]}}
    end;

handle_call({request, rt, Msg}, From, #state{rt = RtNl, curseq = Seq} = State) ->
    Req = nl_rt_enc(prepare_request(Msg, Seq)),
    NewState = register_request(Seq, From, State),
    gen_socket:send(RtNl, Req),
    {noreply, NewState};

handle_call({request, ct, Msg}, From, #state{ct = CtNl, curseq = Seq} = State) ->
    Req = nl_ct_enc(prepare_request(Msg, Seq)),
    NewState = register_request(Seq, From, State),
    gen_socket:send(CtNl, Req),
    {noreply, NewState}.

handle_cast({send, rt, Msg}, #state{rt = RtNl} = State) ->
    gen_socket:send(RtNl, Msg),
    {noreply, State};

handle_cast({send, ct, Msg}, #state{ct = CtNl} = State) ->
    gen_socket:send(CtNl, Msg),
    {noreply, State};

handle_cast(stop, State) ->
	{stop, normal, State}.

handle_info({Socket, input_ready}, #state{ct = Socket} = State0) ->
    State = handle_socket_data(Socket, ct, ctnetlink, fun nl_ct_dec/1, State0),
    ok = gen_socket:input_event(Socket, true),
    {noreply, State};

handle_info({Socket, input_ready}, #state{rt = Socket} = State0) ->
    State = handle_socket_data(Socket, rt, rtnetlink, fun nl_rt_dec/1, State0),
    ok = gen_socket:input_event(Socket, true),
    {noreply, State};

handle_info({Socket, input_ready}, State0) ->
    State = handle_socket_data(Socket, {s, Socket}, raw, fun(X) -> {Socket, X} end, State0),
    ok = gen_socket:input_event(Socket, true),
    {noreply, State};

handle_info({'DOWN', _Ref, process, Pid, _Reason}, #state{subscribers = Sub} = State) ->
    lager:debug("~p:Unsubscribe ~p~n", [?MODULE, Pid]),
    {noreply, State#state{subscribers = lists:delete(Pid, Sub)}};

handle_info(Msg, State) ->
    lager:warning("got Message ~p~n", [Msg]),
    {noreply, State}.

terminate(Reason, _State) ->
    lager:debug("~p terminate:~p~n", [?MODULE, Reason]),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

handle_socket_data(Socket, NlType, SubscriptionType, Decode, #state{subscribers = Sub} = State) ->
    case gen_socket:recvfrom(Socket, 128 * 1024) of
	{ok, _Sender, Data} ->
	    %%  lager:debug("~p got: ~p~n", [NlType, Decode(Data)]),
	    Subs = lists:filter(fun(Elem) ->
					lists:member(NlType, Elem#subscription.types)
				end, Sub),
	    handle_messages(SubscriptionType, Decode(Data), Subs, State);

	Other ->
	    lager:error("~p: ~p~n", [NlType, Other]),
	    State
    end.

%%
%% gen_server internal functions
%%

notify(_SubSys, _Pids, []) ->
    ok;
notify(SubSys, Pids, Msgs) ->
    lists:foreach(fun(Pid) -> Pid#subscription.pid ! {SubSys, Msgs} end, Pids).

-spec process_maybe_multipart(InputMsgs :: [netlink_record() | #netlink{}],
                              MsgBuf    :: [netlink_record()]) ->
        {incomplete, NewMsgBuf :: [netlink_record()]} |
        {done, MsgGrp :: [netlink_record()], RestInput :: [netlink_record() | #netlink{}]}.

process_maybe_multipart([], MsgBuf) ->
    {incomplete, MsgBuf};
process_maybe_multipart([Msg | Rest], MsgBuf) ->
    Type = element(2, Msg),     % Msg may be arbitrary netlink record
    Flags = element(3, Msg),
    MsgSeq = element(4, Msg),

    case Type of
        done ->
            {done, MsgSeq, lists:reverse(MsgBuf), Rest};
        _ ->
            case proplists:get_bool(multi, Flags) of
                false -> {done, MsgSeq, [Msg], Rest};
                true  -> process_maybe_multipart(Rest, [Msg | MsgBuf])
            end
    end.

-spec handle_messages(atom(), InputMsgs :: [netlink_record() | #netlink{}],
                      [#subscription{}], #state{}) -> #state{}.

handle_messages(raw, Msg, Subs, State) ->
    spawn(?MODULE, notify, [s, Subs, Msg]),
    State;
handle_messages(_SubSys, [], _Subs, State) ->
    State#state{msgbuf = []};
handle_messages(SubSys, Msgs, Subs, State) ->
    case process_maybe_multipart(Msgs, State#state.msgbuf) of
        {incomplete, MsgBuf} ->
            State#state{msgbuf = MsgBuf};
        {done, MsgSeq, MsgGrp, Rest} ->
            NewState = case is_request_reply(MsgSeq, State) of
                true  -> send_request_reply(MsgSeq, MsgGrp, State);
                false -> spawn(?MODULE, notify, [SubSys, Subs, MsgGrp]),
                         State
            end,
            handle_messages(SubSys, Rest, Subs, NewState#state{msgbuf = []})
    end.

-spec prepare_request(netlink_record(), non_neg_integer()) -> netlink_record().
prepare_request(Msg0, Seq) ->
    % Msg0 may be arbitrary netlink record
    Flags = element(3, Msg0),
    Msg1 = setelement(3, Msg0, [request | Flags]),
    setelement(4, Msg1, Seq).

register_request(Seq, From, #state{requests = Requests} = State) ->
    NextSeq = case (Seq + 1) rem 16#FFFFFFFF of
        0 -> 16#FF;
        X -> X
    end,
    State#state{
        requests = gb_trees:insert(Seq, From, Requests),
        curseq = NextSeq
    }.

-spec is_request_reply(integer(), #state{}) -> boolean().
is_request_reply(MsgSeq, #state{requests = Request}) ->
    gb_trees:is_defined(MsgSeq, Request).

-spec send_request_reply(integer(), [netlink_record(), ...], #state{}) -> #state{}.
send_request_reply(MsgSeq, Reply, #state{requests = Requests} = State) ->
    From = gb_trees:get(MsgSeq, Requests),

    gen_server:reply(From, {ok, Reply}),
    State#state{requests = gb_trees:delete(MsgSeq, Requests)}.

socket(Family, Type, Protocol, Opts) ->
    case proplists:get_value(netns, Opts) of
	undefined ->
	    gen_socket:socket(Family, Type, Protocol);
	NetNs ->
	    gen_socket:socketat(NetNs, Family, Type, Protocol)
    end.
