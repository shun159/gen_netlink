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
