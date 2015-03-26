% vim: set foldmethod=indent:
-module(mysql_sync_recv).

-include("mysql_conn.hrl").

-export([start_link/4, read/1, get_packet/1, stop_link/1
	]).

-define(Log(LogFun,Level,Msg),
	LogFun(?MODULE, ?LINE,Level,fun()-> {Msg,[]} end)).
-define(Log2(LogFun,Level,Msg,Params),
	LogFun(?MODULE, ?LINE,Level,fun()-> {Msg,Params} end)).
-define(L(Msg), io:format("~p:~b ~p ~n", [?MODULE, ?LINE, Msg])).

%%%	Packet :== {PacketData, Num}
%%%


start_link(Host, Port, LogFun, RecvTimeout)
	when is_list(Host), is_integer(Port); is_tuple(Host), is_integer(Port) ->

   init(Host, Port, LogFun, RecvTimeout)
.

%% return: {ok, #connect}
init(Host, Port, LogFun, RecvTimeout) ->
	case gen_tcp:connect(Host, Port, [binary, {packet, 0}, {active, false} ]) of
	{ok, Sock} ->
		{ok, read(#connect{
			socket  = Sock,
			log_fun = LogFun,
			recv_timeout = RecvTimeout
		})};
	E ->
		LogFun(?MODULE, ?LINE, error,
		   fun() ->
			   {"init: Failed connecting to ~p:~p : ~p",
				[Host, Port, E]}
		   end),
		Msg = lists:flatten(io_lib:format("connect failed : ~p", [E])),
		{error, cannot_connect, Msg}
	end
.

stop_link(Conn) ->
	gen_tcp:close(Conn#connect.socket).

%% return: #connect | {error, Reason}
read(State) ->
	LogFun = State#connect.log_fun,
	ReadIter = fun(IntState) ->
			Sock = IntState#connect.socket,
			Rez = gen_tcp:recv(Sock, 0, IntState#connect.recv_timeout),

			% calculate wait_time only for first packet
			IntState2 = case IntState#connect.query_started of
				0 -> IntState;
				_ ->
					IntState#connect {
						wait_time = timer:now_diff(erlang:now(),
							IntState#connect.query_started),
						query_started = 0
					}
			end,

			case Rez of
				{ok, InData} ->
					LogFun(?MODULE, ?LINE, debug,
						fun() ->{
						   "read: Read from Socket:~n  '~s'~n  (~p)",
						   [InData, InData]
						} end),
					read( IntState2#connect{
						buf = <<(IntState2#connect.buf)/bytes, InData/bytes>>
					});

				{error, Reason} ->
					LogFun(?MODULE, ?LINE, error,
						fun() ->
						   { "read: Socket ~p closed : ~p", [Sock, Reason] }
						end),
					{error, connection_died, Reason}
			end
		end, % ~ ReadIter = fun(IntState)

	%LogFun(?MODULE, ?LINE, error,
	%	fun() -> {
	%		"read called. buf: '~s' (~p)", [State#connect.buf, State#connect.buf]
	%	}end),
	State#connect{ reader = ReadIter }
.

%% return: {ok, #connect, Packet} | {error, ErrCode, Reason}
get_packet(State) ->
	#connect { buf=Data, reader = ReadIter } = State,
	(State#connect.log_fun)(?MODULE, ?LINE, debug,
		fun() -> {
			"get_packet: Connect:~n  ~p", [State]
		}end),
	case extract_packet(Data, State ) of
		{ok, State2, Packet, Rest} ->
			(State2#connect.log_fun)(?MODULE, ?LINE, debug,
				fun() -> {
					"get_packet:~n  buf: (~p)~n  split to packet (~p)~n"
					"  and rest (~p)",
					[Data, Packet, Rest]
				}end),

			{ ok, State2#connect{ buf = Rest }, Packet };
		{not_enough_data, State2} ->
			?Log2( (State2#connect.log_fun), debug,
					"get_packet: not_enough_data, call ReadIter", []),

			case ReadIter(State2) of
				{error, Code, Reason} ->
					{error, Code, Reason};
				State3 ->
					get_packet( State3 )
			end;
		E ->
			{error, unexpected_error, E}
	end
.

%% return: {Packet, Rest} | not_enough_data | unexpected_seqnum
extract_packet(Data, State) when State#connect.seqnum==256 ->
	extract_packet(Data, State#connect { seqnum = 0 });
extract_packet(Data, State) ->
	ExpectedSeqNum = State#connect.seqnum,
	case Data of
	<<Length:24/little, ExpectedSeqNum:8, D/binary>> ->
		if
		Length =< size(D) ->
			State2 = State#connect{ seqnum = ExpectedSeqNum + 1 },
			{Packet, Rest} = split_binary(D, Length),
			?Log2( (State#connect.log_fun), debug,
					"extract_packet: extract ~w bytes:~n  '~s'~n  (~p)~n",
					[Length, D, D]),

			{ok, State2, Packet, Rest};
		true ->
			(State#connect.log_fun)(?MODULE, ?LINE, debug,
				fun() -> {
					"extract_packet: extract ~w bytes:~n  '~s'~n  (~p)~n",
					[Length, D, D]
				}end),
			{not_enough_data, State}
		end;
	<<_Length:24/little, Num:8, _/binary>> ->
		(State#connect.log_fun)(?MODULE, ?LINE, error,
		   fun() ->
			   { "extract_packet: unexpected seqnum ~w received, expected: ~w~nConnection: ~p~n",
				[Num, ExpectedSeqNum, State] }
		   end),
		unexpected_seqnum;
	_ ->
		{not_enough_data, State}
	end
.


