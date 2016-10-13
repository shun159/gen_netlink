%%%-------------------------------------------------------------------
%%% @author Andreas Schultz <aschultz@tpip.net>
%%% @copyright (C) 2011, Andreas Schultz
%%% @doc
%%%
%%% @end
%%% Created : 29 Jun 2011 by Andreas Schultz <aschultz@tpip.net>
%%%-------------------------------------------------------------------
-module(netlink_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").
-include("../include/netlink.hrl").

-define(equal(Expected, Actual),
    (fun (Expected@@@, Expected@@@) -> true;
         (Expected@@@, Actual@@@) ->
             ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
                    [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
             false
     end)(Expected, Actual) orelse error(badmatch)).

conntrack_new() ->
	<<196,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,2,0,0,0,52,0,1,128,20,0,
      1,128,8,0,1,0,192,168,2,24,8,0,2,0,192,168,2,9,28,0,2,128,5,0,1,0,6,0,0,
      0,6,0,2,0,215,100,0,0,6,0,3,0,0,25,0,0,52,0,2,128,20,0,1,128,8,0,1,0,192,
      168,2,9,8,0,2,0,192,168,2,24,28,0,2,128,5,0,1,0,6,0,0,0,6,0,2,0,0,25,0,0,
      6,0,3,0,215,100,0,0,8,0,12,0,53,230,153,0,8,0,3,0,0,0,1,142,8,0,7,0,0,0,
      0,60,48,0,4,128,44,0,1,128,5,0,1,0,5,0,0,0,5,0,2,0,7,0,0,0,5,0,3,0,7,0,0,
      0,6,0,4,0,55,0,0,0,6,0,5,0,35,0,0,0>>.

rt_newneigh_1() ->
	<<76,0,0,0,28,0,0,0,0,0,0,0,0,0,0,0,2,0,0,0,5,0,0,0,2,0,0,1,
      8,0,1,0,192,168,2,3,10,0,2,0,0,14,12,186,3,162,0,0,8,0,4,0,4,0,0,0,20,0,
      3,0,0,0,0,0,0,0,0,0,0,0,0,0,4,0,0,0>>.

rt_newneigh_2() ->
	<<88,0,0,0,28,0,0,0,0,0,0,0,0,0,0,0,10,0,0,0,5,0,0,0,2,0,0,
      1,20,0,1,0,32,1,6,248,18,217,0,0,0,0,0,0,0,0,0,9,10,0,2,0,0,80,86,174,41,
      172,0,0,8,0,4,0,1,0,0,0,20,0,3,0,33,1,0,0,33,1,0,0,0,0,0,0,3,0,0,0>>.

rt_delroute() ->
	<<156,0,0,0,25,0,0,0,0,0,0,0,0,0,0,0,10,128,0,0,255,0,0,1,0,
      2,0,0,8,0,15,0,255,0,0,0,20,0,1,0,255,2,0,0,0,0,0,0,0,0,0,0,0,0,0,251,28,
      0,8,0,8,0,2,0,220,5,0,0,8,0,8,0,160,5,0,0,8,0,10,0,255,255,255,255,20,0,
      5,0,255,2,0,0,0,0,0,0,0,0,0,0,0,0,0,251,8,0,4,0,5,0,0,0,8,0,6,0,0,0,0,0,
      36,0,12,0,0,0,0,0,0,18,0,0,0,0,0,0,0,0,0,0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0>>.

rt_newprefix() ->
	<<60,0,0,0,52,0,0,0,0,0,0,0,0,0,0,0,10,0,0,0,5,0,0,0,3,64,
      3,0,20,0,1,0,32,1,6,248,18,217,0,0,0,0,0,0,0,0,0,0,12,0,2,0,128,58,9,0,0,
      141,39,0>>.

rt_newlink_1() ->
	<<8,2,0,0,16,0,0,0,0,0,0,0,0,0,0,0,10,0,1,0,6,0,0,0,3,16,
      1,0,0,0,0,0,10,0,3,0,118,108,97,110,52,0,0,0,10,0,1,0,0,25,185,71,250,19,
      0,0,8,0,4,0,220,5,0,0,8,0,5,0,5,0,0,0,192,1,12,0,8,0,1,0,0,0,0,128,20,0,
      5,0,255,255,0,0,108,53,74,4,192,16,0,0,100,0,0,0,120,0,2,0,0,0,0,0,64,0,
      0,0,220,5,0,0,1,0,0,0,1,0,0,0,1,0,0,0,1,0,0,0,3,0,0,0,144,1,0,0,100,0,0,
      0,0,0,0,0,128,58,9,0,128,81,1,0,5,0,0,0,88,2,0,0,16,0,0,0,0,0,0,0,1,0,0,
      0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,1,0,0,0,0,0,0,0,252,0,3,0,31,0,0,0,0,0,0,0,80,1,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,80,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,87,1,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,80,1,0,0,0,0,0,0,90,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,111,145,0,0,0,0,0,0,79,147,0,0,0,0,0,0,111,145,0,0,0,0,0,0,71,148,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,44,0,6,0,5,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,7,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>.

rt_newlink_2() ->
	<<188,1,0,0,16,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,2,0,0,0,3,16,0,
      0,1,0,0,0,9,0,3,0,101,116,104,49,0,0,0,0,8,0,13,0,232,3,0,0,5,0,16,0,2,0,
      0,0,5,0,17,0,0,0,0,0,8,0,4,0,220,5,0,0,15,0,6,0,112,102,105,102,111,95,
      102,97,115,116,0,0,36,0,14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,128,239,51,
      0,0,201,255,255,19,0,0,8,0,0,0,0,10,0,1,0,0,80,4,77,115,158,0,0,10,0,2,0,
      255,255,255,255,255,255,0,0,96,0,7,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,188,0,23,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,8,0,21,0,0,0,0,0>>.

rt_linkinfo_1() ->
	<<224,1,0,0,16,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,6,0,0,0,2,16,
      0,0,1,0,0,0,10,0,3,0,118,108,97,110,52,0,0,0,8,0,13,0,0,0,0,0,5,0,16,0,2,
      0,0,0,5,0,17,0,0,0,0,0,8,0,4,0,220,5,0,0,8,0,5,0,5,0,0,0,12,0,6,0,110,
      111,113,117,101,117,101,0,36,0,14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,10,0,1,0,0,25,185,71,250,19,0,0,10,0,2,0,255,
      255,255,255,255,255,0,0,96,0,7,0,4,15,0,0,137,18,0,0,218,23,6,0,162,97,7,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,188,0,23,0,4,15,0,0,0,0,0,0,137,18,0,0,0,0,0,0,218,23,6,0,0,0,
      0,0,162,97,7,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,4,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,40,0,18,0,9,0,1,0,118,108,97,110,0,
      0,0,0,24,0,2,0,6,0,1,0,4,0,0,0,12,0,2,0,1,0,0,0,255,255,255,255>>.

rt_linkinfo_complex() ->
	<<172,1,0,0,16,0,2,0,0,0,0,0,0,0,255,255,0,0,4,3,1,0,0,0,
      73,0,1,0,0,0,0,0,7,0,3,0,108,111,0,0,8,0,13,0,0,0,0,0,5,0,16,0,0,0,0,0,5,
      0,17,0,0,0,0,0,8,0,4,0,52,64,0,0,12,0,6,0,110,111,113,117,101,117,101,0,
      36,0,14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,10,0,1,0,0,0,0,0,0,0,0,0,10,0,2,0,0,0,0,0,0,0,0,0,96,0,7,0,154,92,1,0,
      154,92,1,0,104,17,195,0,104,17,195,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,188,0,23,0,154,92,1,0,0,0,0,
      0,154,92,1,0,0,0,0,0,104,17,195,0,0,0,0,0,104,17,195,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,180,1,0,0,16,0,2,0,0,0,0,0,0,0,255,255,0,0,1,0,2,0,0,0,67,16,1,0,0,
      0,0,0,9,0,3,0,101,116,104,48,0,0,0,0,8,0,13,0,232,3,0,0,5,0,16,0,6,0,0,0,
      5,0,17,0,0,0,0,0,8,0,4,0,220,5,0,0,7,0,6,0,109,113,0,0,36,0,14,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16,0,0,0,0,0,0,0,10,0,1,0,0,25,
      185,71,250,19,0,0,10,0,2,0,255,255,255,255,255,255,0,0,96,0,7,0,102,121,
      128,3,212,26,211,2,107,193,223,78,153,82,28,229,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,224,110,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,188,0,23,0,
      102,121,128,3,0,0,0,0,212,26,211,2,0,0,0,0,107,193,223,78,12,0,0,0,153,
      82,28,229,6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,224,110,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,21,0,0,0,0,0,188,1,0,0,16,0,2,
      0,0,0,0,0,0,0,255,255,0,0,1,0,3,0,0,0,3,16,0,0,0,0,0,0,9,0,3,0,101,116,
      104,49,0,0,0,0,8,0,13,0,232,3,0,0,5,0,16,0,2,0,0,0,5,0,17,0,0,0,0,0,8,0,
      4,0,220,5,0,0,15,0,6,0,112,102,105,102,111,95,102,97,115,116,0,0,36,0,14,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10,0,1,
      0,0,14,12,195,185,27,0,0,10,0,2,0,255,255,255,255,255,255,0,0,96,0,7,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,188,0,23,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,21,0,0,0,0,0,
      192,1,0,0,16,0,2,0,0,0,0,0,0,0,255,255,0,0,1,0,4,0,0,0,67,16,1,0,0,0,0,0,
      9,0,3,0,116,97,112,48,0,0,0,0,8,0,13,0,244,1,0,0,5,0,16,0,0,0,0,0,5,0,17,
      0,0,0,0,0,8,0,4,0,220,5,0,0,15,0,6,0,112,102,105,102,111,95,102,97,115,
      116,0,0,36,0,14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,10,0,1,0,210,248,143,101,242,239,0,0,10,0,2,0,255,255,255,255,
      255,255,0,0,96,0,7,0,180,7,0,0,203,163,20,0,177,50,5,0,124,220,111,11,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,188,0,23,0,180,7,0,0,0,0,0,0,203,163,20,0,0,0,0,0,177,50,5,0,0,0,0,
      0,124,220,111,11,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,12,0,18,0,8,0,1,0,116,117,110,0,
      172,1,0,0,16,0,2,0,0,0,0,0,0,0,255,255,0,0,1,0,5,0,0,0,67,16,1,0,0,0,0,0,
      8,0,3,0,98,114,48,0,8,0,13,0,0,0,0,0,5,0,16,0,0,0,0,0,5,0,17,0,0,0,0,0,8,
      0,4,0,220,5,0,0,12,0,6,0,110,111,113,117,101,117,101,0,36,0,14,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10,0,1,0,0,25,
      185,71,250,19,0,0,10,0,2,0,255,255,255,255,255,255,0,0,96,0,7,0,130,41,
      86,2,238,191,6,2,188,192,107,206,93,73,7,165,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,15,195,19,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,188,0,23,0,130,
      41,86,2,0,0,0,0,238,191,6,2,0,0,0,0,188,192,107,206,11,0,0,0,93,73,7,165,
      6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      15,195,19,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,224,1,0,0,16,0,2,0,0,0,0,0,0,0,255,255,0,0,1,
      0,6,0,0,0,2,16,0,0,0,0,0,0,10,0,3,0,118,108,97,110,52,0,0,0,8,0,13,0,0,0,
      0,0,5,0,16,0,2,0,0,0,5,0,17,0,0,0,0,0,8,0,4,0,220,5,0,0,8,0,5,0,5,0,0,0,
      12,0,6,0,110,111,113,117,101,117,101,0,36,0,14,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,10,0,1,0,0,25,185,71,250,19,0,0,
      10,0,2,0,255,255,255,255,255,255,0,0,96,0,7,0,4,15,0,0,137,18,0,0,218,23,
      6,0,162,97,7,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,15,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,188,0,23,0,4,15,0,0,0,0,0,0,137,18,0,0,0,0,0,0,
      218,23,6,0,0,0,0,0,162,97,7,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,4,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,40,0,18,0,9,0,1,0,
      118,108,97,110,0,0,0,0,24,0,2,0,6,0,1,0,4,0,0,0,12,0,2,0,1,0,0,0,255,255,
      255,255,224,1,0,0,16,0,2,0,0,0,0,0,0,0,255,255,0,0,1,0,7,0,0,0,67,16,1,0,
      0,0,0,0,12,0,3,0,118,108,97,110,49,48,49,0,8,0,13,0,0,0,0,0,5,0,16,0,6,0,
      0,0,5,0,17,0,0,0,0,0,8,0,4,0,220,5,0,0,8,0,5,0,5,0,0,0,12,0,6,0,110,111,
      113,117,101,117,101,0,36,0,14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,10,0,1,0,0,25,185,71,250,19,0,0,10,0,2,0,255,255,
      255,255,255,255,0,0,96,0,7,0,0,0,0,0,129,3,0,0,0,0,0,0,162,155,1,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,188,0,23,0,0,0,0,0,0,0,0,0,129,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,162,155,1,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,40,0,18,0,9,0,1,0,118,108,97,110,0,0,0,0,24,0,
      2,0,6,0,1,0,101,0,0,0,12,0,2,0,1,0,0,0,255,255,255,255,224,1,0,0,16,0,2,
      0,0,0,0,0,0,0,255,255,0,0,1,0,8,0,0,0,67,16,1,0,0,0,0,0,12,0,3,0,118,108,
      97,110,49,48,51,0,8,0,13,0,0,0,0,0,5,0,16,0,6,0,0,0,5,0,17,0,0,0,0,0,8,0,
      4,0,220,5,0,0,8,0,5,0,5,0,0,0,12,0,6,0,110,111,113,117,101,117,101,0,36,
      0,14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      10,0,1,0,0,25,185,71,250,19,0,0,10,0,2,0,255,255,255,255,255,255,0,0,96,
      0,7,0,0,0,0,0,128,3,0,0,0,0,0,0,87,155,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,188,0,23,0,0,0,0,0,0,0,
      0,0,128,3,0,0,0,0,0,0,0,0,0,0,0,0,0,0,87,155,1,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      40,0,18,0,9,0,1,0,118,108,97,110,0,0,0,0,24,0,2,0,6,0,1,0,103,0,0,0,12,0,
      2,0,1,0,0,0,255,255,255,255>>.

nfq_unbind() ->
    <<28,0,0,0,2,3,5,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,1,0,4,0,0,2>>.
nfq_unbind_answer() ->
    <<36,0,0,0,2,0,0,0,0,0,0,0,174,4,0,0,0,0,0,0,28,0,0,0,2,3,5,0,0,0,0,0,0,0,0,0>>.

nfq_bind_queue() ->
    <<28,0,0,0,2,3,5,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,1,0,3,0,0,2>>.

nfq_bind_queue_answer() ->
    <<36,0,0,0,2,0,0,0,0,0,0,0,189,4,0,0,0,0,0,0,28,0,0,0,2,3,5,0,0,0,0,0,0,0,0,0>>.

nfq_bind_socket() ->
    <<28,0,0,0,2,3,5,0,0,0,0,0,0,0,0,0,0,0,0,0,8,0,1,0,1,0,0,0>>.

nfq_bind_socket_answer() ->
    <<36,0,0,0,2,0,0,0,0,0,0,0,189,4,0,0,0,0,0,0,28,0,0,0,2,3,5,0,0,0,0,0,0,0,0,0>>.

nfq_set_copy_mode() ->
    <<32,0,0,0,2,3,5,0,0,0,0,0,0,0,0,0,0,0,0,0,9,0,2,0,0,0,255,255,2,0,0,0>>.

nfq_set_copy_mode_answer() ->
    <<36,0,0,0,2,0,0,0,0,0,0,0,189,4,0,0,0,0,0,0,32,0,0,0,2,3,5,0,0,0,0,0,0,0,0,0>>.

nfq_set_verdict() ->
    <<32,0,0,0,1,3,1,0,0,0,0,0,0,0,0,0,0,0,0,0,12,0,2,0,0,0,0,1,0,0,0,1>>.

nfq_packet() ->
    <<176,0,0,0,0,3,0,0,0,0,0,0,0,0,0,0,2,0,0,0,11,0,1,0,0,0,
      0,1,8,0,0,0,8,0,5,0,0,0,0,11,8,0,3,0,8,12,0,0,16,0,9,0,
      0,6,0,0,0,80,86,150,196,3,0,0,20,0,4,0,0,0,0,0,85,167,
      197,137,0,0,0,0,0,10,209,138,92,0,10,0,69,192,0,88,87,
      34,0,0,1,89,213,56,172,28,0,17,224,0,0,5,2,1,0,52,172,
      28,0,17,0,0,0,0,0,0,0,2,0,0,1,16,0,7,94,156,255,255,255,
      0,0,10,2,1,0,0,0,40,172,28,0,17,172,28,0,32,10,0,0,1,
      172,28,0,16,231,148,79,84,211,63,84,12,100,46,35,199,
      185,157,63,9>>.

nft_requests() ->
    [<<16#14, 16#00, 16#00, 16#00, 16#10, 16#00, 16#01, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#0a, 16#00, 16#14, 16#00, 16#00, 16#00, 16#09, 16#0a, 16#05, 16#00, 16#01, 16#00, 16#00, 16#00,
       16#00, 16#00, 16#00, 16#00, 16#02, 16#00, 16#00, 16#00, 16#14, 16#00, 16#00, 16#00, 16#11, 16#00, 16#01, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#02, 16#00, 16#0a, 16#00>>,
     <<16#14, 16#00, 16#00, 16#00, 16#10, 16#0a, 16#01, 16#00, 16#03, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#00, 16#00, 16#00, 16#00>>,
     <<16#14, 16#00, 16#00, 16#00, 16#01, 16#0a, 16#01, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#00, 16#00, 16#00, 16#00>>,
     <<16#1c, 16#00, 16#00, 16#00, 16#01, 16#0a, 16#05, 16#00, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#08, 16#00, 16#01, 16#00, 16#72, 16#61, 16#77, 16#00>>,
     <<16#1c, 16#00, 16#00, 16#00, 16#0a, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#08, 16#00, 16#01, 16#00, 16#72, 16#61, 16#77, 16#00>>,
     <<16#14, 16#00, 16#00, 16#00, 16#04, 16#0a, 16#01, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00>>,
     <<16#14, 16#00, 16#00, 16#00, 16#07, 16#0a, 16#01, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00>>,
     <<16#20, 16#00, 16#00, 16#00, 16#01, 16#0a, 16#05, 16#00, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#6d, 16#61, 16#6e, 16#67, 16#6c, 16#65, 16#00, 16#00>>,
     <<16#20, 16#00, 16#00, 16#00, 16#0a, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#6d, 16#61, 16#6e, 16#67, 16#6c, 16#65, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#0d, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#6d, 16#61, 16#6e, 16#67, 16#6c, 16#65, 16#00, 16#00,
       16#09, 16#00, 16#02, 16#00, 16#6d, 16#61, 16#70, 16#30, 16#00, 16#00, 16#00, 16#00>>,
     <<16#14, 16#00, 16#00, 16#00, 16#04, 16#0a, 16#01, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00>>,
     <<16#14, 16#00, 16#00, 16#00, 16#07, 16#0a, 16#01, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00>>,
     <<16#30, 16#00, 16#00, 16#00, 16#00, 16#0b, 16#05, 16#00, 16#f5, 16#c0, 16#c1, 16#55, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#73, 16#6f, 16#63, 16#6b, 16#65, 16#74, 16#00, 16#00,
       16#08, 16#00, 16#02, 16#00, 16#00, 16#00, 16#00, 16#02, 16#08, 16#00, 16#03, 16#00, 16#00, 16#00, 16#00, 16#00>>,
     <<16#30, 16#00, 16#00, 16#00, 16#00, 16#0b, 16#05, 16#00, 16#f5, 16#c0, 16#c1, 16#55, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#73, 16#6f, 16#63, 16#6b, 16#65, 16#74, 16#00, 16#00,
       16#08, 16#00, 16#02, 16#00, 16#00, 16#00, 16#00, 16#02, 16#08, 16#00, 16#03, 16#00, 16#00, 16#00, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#00, 16#0b, 16#05, 16#00, 16#f5, 16#c0, 16#c1, 16#55, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#08, 16#00, 16#01, 16#00, 16#73, 16#65, 16#74, 16#00, 16#08, 16#00, 16#02, 16#00,
       16#00, 16#00, 16#00, 16#04, 16#08, 16#00, 16#03, 16#00, 16#00, 16#00, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#00, 16#0b, 16#05, 16#00, 16#f5, 16#c0, 16#c1, 16#55, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#08, 16#00, 16#01, 16#00, 16#73, 16#65, 16#74, 16#00, 16#08, 16#00, 16#02, 16#00,
       16#00, 16#00, 16#00, 16#04, 16#08, 16#00, 16#03, 16#00, 16#00, 16#00, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#00, 16#0b, 16#05, 16#00, 16#f5, 16#c0, 16#c1, 16#55, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#08, 16#00, 16#01, 16#00, 16#73, 16#65, 16#74, 16#00, 16#08, 16#00, 16#02, 16#00,
       16#00, 16#00, 16#00, 16#04, 16#08, 16#00, 16#03, 16#00, 16#00, 16#00, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#00, 16#0b, 16#05, 16#00, 16#f5, 16#c0, 16#c1, 16#55, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#08, 16#00, 16#01, 16#00, 16#73, 16#65, 16#74, 16#00, 16#08, 16#00, 16#02, 16#00,
       16#00, 16#00, 16#00, 16#04, 16#08, 16#00, 16#03, 16#00, 16#00, 16#00, 16#00, 16#00>>,
     %% RTM_GETLINK
     %% <<16#14, 16#00, 16#00, 16#00, 16#12, 16#00, 16#01, 16#03, 16#f5, 16#c0, 16#c1, 16#55, 16#00, 16#00, 16#00, 16#00,
     %%   16#11, 16#00, 16#00, 16#00>>,
     <<16#1c, 16#00, 16#00, 16#00, 16#01, 16#0a, 16#05, 16#00, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#08, 16#00, 16#01, 16#00, 16#6e, 16#61, 16#74, 16#00>>,
     <<16#1c, 16#00, 16#00, 16#00, 16#0a, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#08, 16#00, 16#01, 16#00, 16#6e, 16#61, 16#74, 16#00>>,
     <<16#14, 16#00, 16#00, 16#00, 16#04, 16#0a, 16#01, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00>>,
     <<16#14, 16#00, 16#00, 16#00, 16#07, 16#0a, 16#01, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00>>,
     <<16#20, 16#00, 16#00, 16#00, 16#01, 16#0a, 16#05, 16#00, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#66, 16#69, 16#6c, 16#74, 16#65, 16#72, 16#00, 16#00>>,
     <<16#20, 16#00, 16#00, 16#00, 16#0a, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#66, 16#69, 16#6c, 16#74, 16#65, 16#72, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#0d, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#66, 16#69, 16#6c, 16#74, 16#65, 16#72, 16#00, 16#00,
       16#09, 16#00, 16#02, 16#00, 16#6d, 16#61, 16#70, 16#30, 16#00, 16#00, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#0d, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#66, 16#69, 16#6c, 16#74, 16#65, 16#72, 16#00, 16#00,
       16#09, 16#00, 16#02, 16#00, 16#6d, 16#61, 16#70, 16#31, 16#00, 16#00, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#0d, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#66, 16#69, 16#6c, 16#74, 16#65, 16#72, 16#00, 16#00,
       16#09, 16#00, 16#02, 16#00, 16#6d, 16#61, 16#70, 16#32, 16#00, 16#00, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#0d, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#66, 16#69, 16#6c, 16#74, 16#65, 16#72, 16#00, 16#00,
       16#09, 16#00, 16#02, 16#00, 16#6d, 16#61, 16#70, 16#33, 16#00, 16#00, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#0d, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#66, 16#69, 16#6c, 16#74, 16#65, 16#72, 16#00, 16#00,
       16#09, 16#00, 16#02, 16#00, 16#6d, 16#61, 16#70, 16#34, 16#00, 16#00, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#0d, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#66, 16#69, 16#6c, 16#74, 16#65, 16#72, 16#00, 16#00,
       16#09, 16#00, 16#02, 16#00, 16#6d, 16#61, 16#70, 16#35, 16#00, 16#00, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#0d, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#66, 16#69, 16#6c, 16#74, 16#65, 16#72, 16#00, 16#00,
       16#09, 16#00, 16#02, 16#00, 16#6d, 16#61, 16#70, 16#36, 16#00, 16#00, 16#00, 16#00>>,
     <<16#2c, 16#00, 16#00, 16#00, 16#0d, 16#0a, 16#05, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00, 16#0b, 16#00, 16#01, 16#00, 16#66, 16#69, 16#6c, 16#74, 16#65, 16#72, 16#00, 16#00,
       16#09, 16#00, 16#02, 16#00, 16#6d, 16#61, 16#70, 16#37, 16#00, 16#00, 16#00, 16#00>>,
     <<16#14, 16#00, 16#00, 16#00, 16#04, 16#0a, 16#01, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00>>,
     <<16#14, 16#00, 16#00, 16#00, 16#07, 16#0a, 16#01, 16#03, 16#05, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00, 16#00,
       16#02, 16#00, 16#00, 16#00>>].

genl_request() ->
    <<16#24, 16#00, 16#00, 16#00, 16#10, 16#00, 16#05, 16#00, 16#77, 16#ce, 16#08, 16#56, 16#00, 16#00, 16#00, 16#00,
      16#03, 16#01, 16#00, 16#00, 16#06, 16#00, 16#01, 16#00, 16#10, 16#00, 16#00, 16#00, 16#08, 16#00, 16#02, 16#00,
      16#67, 16#74, 16#70, 16#00>>.

ipvs_metrics() ->
    {
        <<76,1,0,0,27,0,2,0,3,0,0,0,229,56,174,198,5,1,0,0,56,1,2,0,20,0,1,0,4,2,2,2,0,
        0,0,0,0,0,0,0,0,0,0,0,6,0,2,0,0,80,0,0,8,0,3,0,0,0,0,0,8,0,4,0,1,0,0,0,8,0,5,
        0,0,0,0,0,8,0,6,0,0,0,0,0,8,0,7,0,0,0,0,0,8,0,8,0,0,0,0,0,8,0,9,0,0,0,0,0,6,
        0,11,0,2,0,0,0,92,0,10,0,8,0,1,0,5,0,0,0,8,0,2,0,7,0,0,0,8,0,3,0,0,0,0,0,12,
        0,4,0,164,1,0,0,0,0,0,0,12,0,5,0,0,0,0,0,0,0,0,0,8,0,6,0,0,0,0,0,8,0,7,0,0,0,
        0,0,8,0,8,0,0,0,0,0,8,0,9,0,0,0,0,0,8,0,10,0,0,0,0,0,124,0,12,0,12,0,1,0,5,0,
        0,0,0,0,0,0,12,0,2,0,7,0,0,0,0,0,0,0,12,0,3,0,0,0,0,0,0,0,0,0,12,0,4,0,164,1,
        0,0,0,0,0,0,12,0,5,0,0,0,0,0,0,0,0,0,12,0,6,0,0,0,0,0,0,0,0,0,12,0,7,0,0,0,0,
        0,0,0,0,0,12,0,8,0,0,0,0,0,0,0,0,0,12,0,9,0,0,0,0,0,0,0,0,0,12,0,10,0,0,0,0,
        0,0,0,0,0,76,1,0,0,27,0,2,0,3,0,0,0,229,56,174,198,5,1,0,0,56,1,2,0,20,0,1,0,
        216,58,192,14,0,0,0,0,0,0,0,0,0,0,0,0,6,0,2,0,0,80,0,0,8,0,3,0,0,0,0,0,8,0,4,
        0,1,0,0,0,8,0,5,0,0,0,0,0,8,0,6,0,0,0,0,0,8,0,7,0,0,0,0,0,8,0,8,0,0,0,0,0,8,
        0,9,0,0,0,0,0,6,0,11,0,2,0,0,0,92,0,10,0,8,0,1,0,12,0,0,0,8,0,2,0,54,0,0,0,8,
        0,3,0,40,0,0,0,12,0,4,0,192,11,0,0,0,0,0,0,12,0,5,0,64,23,0,0,0,0,0,0,8,0,6,
        0,0,0,0,0,8,0,7,0,0,0,0,0,8,0,8,0,0,0,0,0,8,0,9,0,0,0,0,0,8,0,10,0,0,0,0,0,
        124,0,12,0,12,0,1,0,12,0,0,0,0,0,0,0,12,0,2,0,54,0,0,0,0,0,0,0,12,0,3,0,40,0,
        0,0,0,0,0,0,12,0,4,0,192,11,0,0,0,0,0,0,12,0,5,0,64,23,0,0,0,0,0,0,12,0,6,0,
        0,0,0,0,0,0,0,0,12,0,7,0,0,0,0,0,0,0,0,0,12,0,8,0,0,0,0,0,0,0,0,0,12,0,9,0,0,
        0,0,0,0,0,0,0,12,0,10,0,0,0,0,0,0,0,0,0>>,
        [{netlink,ipvs,
            [multi],
            3,3333306597,
            {new_dest,1,0,
                [{dest,[{address,<<4,2,2,2,0,0,0,0,0,0,0,0,0,0,0,0>>},
                    {port,80},
                    {fwd_method,0},
                    {weight,1},
                    {u_threshold,0},
                    {l_threshold,0},
                    {active_conns,0},
                    {inact_conns,0},
                    {persist_conns,0},
                    {addr_family,2},
                    {stats,[{conns,5},
                        {inpkts,7},
                        {outpkts,0},
                        {inbytes,420},
                        {outbytes,0},
                        {cps,0},
                        {inpps,0},
                        {outpps,0},
                        {inbps,0},
                        {outbps,0}]},
                    {stats64,[{conns,5},
                        {inpkts,7},
                        {outpkts,0},
                        {inbytes,420},
                        {outbytes,0},
                        {cps,0},
                        {inpps,0},
                        {outpps,0},
                        {inbps,0},
                        {outbps,0}]}]}]}},
            {netlink,ipvs,
                [multi],
                3,3333306597,
                {new_dest,1,0,
                    [{dest,[{address,<<216,58,192,14,0,0,0,0,0,0,0,0,0,0,0,0>>},
                        {port,80},
                        {fwd_method,0},
                        {weight,1},
                        {u_threshold,0},
                        {l_threshold,0},
                        {active_conns,0},
                        {inact_conns,0},
                        {persist_conns,0},
                        {addr_family,2},
                        {stats,[{conns,12},
                            {inpkts,54},
                            {outpkts,40},
                            {inbytes,3008},
                            {outbytes,5952},
                            {cps,0},
                            {inpps,0},
                            {outpps,0},
                            {inbps,0},
                            {outbps,0}]},
                        {stats64,[{conns,12},
                            {inpkts,54},
                            {outpkts,40},
                            {inbytes,3008},
                            {outbytes,5952},
                            {cps,0},
                            {inpps,0},
                            {outpps,0},
                            {inbps,0},
                            {outbps,0}]}]}]}}]
    }.


%%--------------------------------------------------------------------
%% @spec suite() -> Info
%% Info = [tuple()]
%% @end
%%--------------------------------------------------------------------
suite() ->
	[{timetrap,{seconds,30}}].

test_conntrack_new(_Config) ->
	Msg = conntrack_new(),
	Msg = netlink_codec:nl_ct_enc(netlink_codec:nl_ct_dec(Msg)),
    ok.

test_rt_newneigh_1(_Config) ->
	Msg = rt_newneigh_1(),
	Msg = netlink_codec:nl_rt_enc(netlink_codec:nl_rt_dec(Msg)),
    ok.

test_rt_newneigh_2(_Config) ->
	Msg = rt_newneigh_2(),
	Msg = netlink_codec:nl_rt_enc(netlink_codec:nl_rt_dec(Msg)),
    ok.

test_rt_delroute(_Config) ->
	Msg = rt_delroute(),
	Msg = netlink_codec:nl_rt_enc(netlink_codec:nl_rt_dec(Msg)),
    ok.

test_rt_newprefix(_Config) ->
	Msg = rt_newprefix(),
	Msg = netlink_codec:nl_rt_enc(netlink_codec:nl_rt_dec(Msg)),
    ok.

test_rt_newlink_1(_Config) ->
	Msg = rt_newlink_1(),
	Msg = netlink_codec:nl_rt_enc(netlink_codec:nl_rt_dec(Msg)),
    ok.

test_rt_newlink_2(_Config) ->
	Msg = rt_newlink_2(),
	Msg = netlink_codec:nl_rt_enc(netlink_codec:nl_rt_dec(Msg)),
    ok.

test_rt_linkinfo_1(_Config) ->
	Msg = rt_linkinfo_1(),
	Msg = netlink_codec:nl_rt_enc(netlink_codec:nl_rt_dec(Msg)),
    ok.

test_rt_linkinfo_complex(_Config) ->
	Msg = rt_linkinfo_complex(),
	Msg = netlink_codec:nl_rt_enc(netlink_codec:nl_rt_dec(Msg)),
    ok.

test_nfq_unbind(_Config) ->
    Msg = nfq_unbind(),
    Msg = netlink_codec:nl_ct_enc(netlink_codec:nl_ct_dec(Msg)),
    ok.

test_nfq_bind_queue(_Config) ->
    Msg = nfq_bind_queue(),
    Msg = netlink_codec:nl_ct_enc(netlink_codec:nl_ct_dec(Msg)),
    ok.

test_nfq_bind_socket(_Config) ->
    Msg = nfq_bind_socket(),
    Msg = netlink_codec:nl_ct_enc(netlink_codec:nl_ct_dec(Msg)),
    ok.

test_nfq_set_copy_mode(_Config) ->
    Msg = nfq_set_copy_mode(),
    Msg = netlink_codec:nl_ct_enc(netlink_codec:nl_ct_dec(Msg)),
    ok.

test_nfq_set_verdict(_Config) ->
    Msg = nfq_set_verdict(),
    Msg = netlink_codec:nl_ct_enc(netlink_codec:nl_ct_dec(Msg)),
    ok.

test_nft_requests(_Config) ->
    lists:foreach(fun(Msg) ->
			  D = netlink_codec:nl_ct_dec(Msg),
			  ct:pal("D: ~p", [D]),
			  ?equal(Msg, netlink_codec:nl_ct_enc(D))
		  end, nft_requests()),
    ok.

test_genl(_Config) ->
    Msg = genl_request(),
    Msg = netlink_codec:nl_enc(?NETLINK_GENERIC, netlink_codec:nl_dec(?NETLINK_GENERIC, Msg)),
    ok.

test_ipvs(_Config) ->
    {EncodedMsg, DecodedMsg} = ipvs_metrics(),
    DecodedMsg = netlink_codec:nl_dec(ipvs, EncodedMsg),
    %% 27 was the original IPVS generic netlink family used to encode this message
    EncodedMsg =  netlink_codec:nl_enc(27, DecodedMsg).

test_tcp_metrics_get_enc(_Config) ->
    GetMsg = <<20, 0, 0, 0, 24, 0, 1, 3, 145, 211, 255, 87, 0, 0, 0, 0, 1, 1, 0, 0>>,
    Family = 24,
    Pid = 0,
    Seq = 1476383633,
    Flags = [?NLM_F_DUMP, request],
    Msg = {netlink, tcp_metrics, Flags, Seq, Pid, {get, 1, 0, []}},
    Data = netlink_codec:nl_enc(Family, Msg),
    ct:pal("got ~p", [Data]),
    ct:pal("exp ~p", [GetMsg]),
    GetMsg =  Data.


all() ->
	[test_conntrack_new,
	 test_rt_newneigh_1, test_rt_newneigh_2, test_rt_delroute,
	 test_rt_newprefix,
	 test_rt_newlink_1, test_rt_newlink_2,
	 test_rt_linkinfo_1, test_rt_linkinfo_complex,
	 test_nfq_unbind, test_nfq_bind_queue,
	 test_nfq_bind_socket, test_nfq_set_copy_mode,
	 test_nfq_set_verdict,
	 test_nft_requests,
	 test_genl, test_ipvs, test_tcp_metrics_get_enc
	].

init_per_suite(Config) ->
	Config.

end_per_suite(_Config) ->
	ok.

