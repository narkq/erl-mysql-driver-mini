% vim: set foldmethod=indent:
-module(mysql_sync_conn).

%%--------------------------------------------------------------------
%% External exports
%%--------------------------------------------------------------------
-export([init/7,
	 fetch/2,
	 quit/1,
	 do_query_without_retrieve_rows/2
	]).

-export([do_recv/1
	]).

-include("mysql_conn.hrl").
-include("mysql.hrl").

-define(SECURE_CONNECTION, 32768).
-define(MYSQL_QUIT_OP, 1).
-define(MYSQL_QUERY_OP, 3).
-define(DEFAULT_STANDALONE_TIMEOUT, 5000).
-define(MYSQL_4_0, 40). %% Support for MySQL 4.0.x
-define(MYSQL_4_1, 41). %% Support for MySQL 4.1.x et 5.0.x

%% Used by transactions to get the state variable for this connection
%% when bypassing the dispatcher.
-define(STATE_VAR, mysql_connection_state).

-define(Log(LogFun,Level,Msg),
	LogFun(?MODULE, ?LINE,Level,fun()-> {Msg,[]} end)).
-define(Log2(LogFun,Level,Msg,Params),
	LogFun(?MODULE, ?LINE,Level,fun()-> {Msg,Params} end)).
-define(L(Msg), io:format("~p:~b ~p ~n", [?MODULE, ?LINE, Msg])).

-define(RECV_TIMEOUT, 600000).

%%%	Conn :== mysql_sync_recv:#state

init(Host, Port, User, Password, Database, LogFun, Encoding) ->
	init(Host, Port, User, Password, Database, LogFun, Encoding, ?RECV_TIMEOUT).

init(Host, Port, User, Password, Database, LogFun, Encoding, Timeout) ->
	case mysql_sync_recv:start_link(Host, Port, LogFun, Timeout) of
	{ok, Conn} ->
		%io:format("init:Connect: ~p~n", [Conn]),
		case mysql_init(Conn, User, Password) of
		{ok, Conn2} ->
			Db = iolist_to_binary(Database),
			case do_query(Conn2, <<"use ", Db/binary>>) of
			{query_error, Conn3, Code, MySQLRes} ->
				?Log2( (Conn3#connect.log_fun), error,
				 "mysql_conn: Failed changing to database "
				 "~p : (~w) ~p",
				 [Database, Code,
				  mysql:get_result_reason(MySQLRes)]),
				{query_error, Conn3, Code, failed_changing_database};

			{error, Code, MySQLRes} ->
				?Log2( (Conn2#connect.log_fun), error,
				 "mysql_conn: cannot select database "
				 "~p : (~w) ~p",
				 [Database, Code,
				  mysql:get_result_reason(MySQLRes)]),
				{error, Code, failed_changing_database};

			%% ResultType: data | updated
			{_ResultType, Conn3, _MySQLRes} ->
				Conn5 = case Encoding of
					undefined -> Conn3;
					_ ->
						EncodingBinary = list_to_binary(atom_to_list(Encoding)),
						{_ResultType, Conn4, _MySQLRes} = do_query(Conn3,
							<<"set names '", EncodingBinary/binary, "'">>),
						Conn4
				end,
				{ok, Conn5}
			end;
		{error, Code, Reason} ->
			{error, Code, Reason}
		end;
	{error, Code, Msg} ->
		?Log2(LogFun, error,
		 "failed connecting to ~p:~p : (~w) ~p",
		 [Host, Port, Code, Msg]),
		{error, Code, Msg}
	end.

%%--------------------------------------------------------------------
%% Function: fetch(Pid, Query, From)
%%           fetch(Pid, Query, From, Timeout)
%%           Pid     = pid(), mysql_conn to send fetch-request to
%%           Queries   = A single binary() query or a list of binary() queries.
%%                     If a list is provided, the return value is the return
%%                     of the last query, or the first query that has
%%                     returned an error. If an error occurs, execution of
%%                     the following queries is aborted.
%%           From    = pid() or term(), use a From of self() when
%%                     using this module for a single connection,
%%                     or pass the gen_server:call/3 From argument if
%%                     using a gen_server to do the querys (e.g. the
%%                     mysql_dispatcher)
%%           Timeout = integer() | infinity, gen_server timeout value
%% Descrip.: Send a query or a list of queries and wait for the result
%%           if running stand-alone (From = self()), but don't block
%%           the caller if we are not running stand-alone
%%           (From = gen_server From).
%% Returns : ok                        | (non-stand-alone mode)
%%           {data, #mysql_result}     | (stand-alone mode)
%%           {updated, #mysql_result}  | (stand-alone mode)
%%           {error, #mysql_result}      (stand-alone mode)
%%           FieldInfo = term()
%%           Rows      = list() of [string()]
%%           Reason    = term()
%%--------------------------------------------------------------------
quit(Conn) ->
	LogFun = Conn#connect.log_fun,
	?Log(LogFun, debug, "do_quit"),
    Packet =  <<?MYSQL_QUIT_OP>>,
    case do_send(Conn#connect{ seqnum = 0}, Packet) of
	{ok, Conn2} ->
		mysql_sync_recv:stop_link(Conn2);
	{error, Code, Reason} ->
	    Msg = io_lib:format("Failed sending QUIT "
				"on socket : ~p",
				[Reason]),
	    {error, Code,  Msg}
    end.


fetch(Conn, Queries) ->
    do_queries(Conn, Queries).


%% return:	{ok, Conn}
mysql_init(Conn, User, Password) ->
	LogFun = Conn#connect.log_fun,
	case do_recv(Conn) of
	{ok, Conn2, Packet} ->
		case greeting(Packet, LogFun) of
		{error, Reason} ->
			{error, Reason} ;
		{ok, Version, Salt1, Salt2, Caps} ->
			?Log2(LogFun, debug, "Connection: ~p", [Conn2]),
			AuthRes =
			case Caps band ?SECURE_CONNECTION of
				?SECURE_CONNECTION ->
					%io:format("do mysql_sync_auth:do_new_auth~n"),
					mysql_sync_auth:do_new_auth(Conn2, User, Password, Salt1, Salt2);
				_ ->
					%io:format("do mysql_sync_auth:do_old_auth~n"),
					mysql_sync_auth:do_old_auth( Conn2, User, Password, Salt1)
			end,
			?Log2(LogFun, debug, "AuthRes: ~p", [AuthRes]),
			case AuthRes of
				{ok, Conn3, <<0:8, _Rest/binary>>} ->
					{ok, Conn3#connect { mysql_version = Version } };
				{ok, _Conn3, <<255:8, Code:16/little, Message/binary>>, _RecvNum} ->
					?Log2(LogFun, error, "init error ~p: ~p",
					 [Code, binary_to_list(Message)]),

					{error, Code, binary_to_list(Message)};
				{ok, _Conn3, RecvPacket} ->
					?Log2(LogFun, error, "init unknown error ~p",
					  [binary_to_list(RecvPacket)]),

					{error, binary_to_list(RecvPacket)};
				{error, Code, Reason} ->
					?Log2(LogFun, error,
					  "init failed receiving data : ~p", [Reason]),
					{error, Code, Reason}
					end
			end;
	{error, Code, Reason} ->
		{error, Code, Reason}
	end.

do_recv(Conn) ->
	mysql_sync_recv:get_packet(Conn).

%%--------------------------------------------------------------------
%% Function: do_send(Sock, Packet, SeqNum, LogFun)
%%           Sock   = term(), gen_tcp socket
%%           Packet = binary()
%%           SeqNum = integer(), packet sequence number
%%           LogFun = undefined | function() with arity 3
%% Descrip.: Send a packet to the MySQL server.
%% Returns : result of gen_tcp:send/2
%%--------------------------------------------------------------------
do_send(Conn, Packet) when is_binary(Packet) ->
	LogFun = Conn#connect.log_fun,
	?Log2(LogFun, debug, "do_send: ~p~nConnect: ~p", [Packet, Conn]),

    Data = <<(size(Packet)):24/little, (Conn#connect.seqnum):8, Packet/binary>>,
    case gen_tcp:send(Conn#connect.socket, Data) of
		ok ->
			{ok, Conn#connect{ seqnum = Conn#connect.seqnum + 1,
				query_started = erlang:now() } };
		{error, Reason} ->
			{error, send_error, Reason}
	end.


%% part of mysql_init/4
greeting(<<255:8, ErrCode:16/little, ErrMessage/binary>>, LogFun) ->
	?Log2(LogFun, error, "init failed ~p: ~p", [ErrCode, binary_to_list(ErrMessage)]),
	{error, ErrCode, binary_to_list(ErrMessage)} ;
greeting(Packet, LogFun) ->
    <<Protocol:8, Rest/binary>> = Packet,
    {Version, Rest2} = asciz(Rest),
    <<_TreadID:32/little, Rest3/binary>> = Rest2,
    {Salt, Rest4} = asciz(Rest3),
    <<Caps:16/little, Rest5/binary>> = Rest4,
    <<ServerChar:16/binary-unit:8, Rest6/binary>> = Rest5,
    {Salt2, _Rest7} = asciz(Rest6),
    ?Log2(LogFun, debug,
	  "greeting version ~p (protocol ~p) salt ~p caps ~p serverchar ~p"
	  "salt2 ~p",
	  [Version, Protocol, Salt, Caps, ServerChar, Salt2]),
	{ok, normalize_version(Version, LogFun), Salt, Salt2, Caps}.

%% part of greeting/2
asciz(Data) when is_binary(Data) ->
    mysql:asciz_binary(Data, []);
asciz(Data) when is_list(Data) ->
    {String, [0 | Rest]} = lists:splitwith(fun (C) ->
						   C /= 0
					   end, Data),
    {String, Rest}.


do_query(Conn, Query) ->
    Query1 = iolist_to_binary(Query),
    ?Log2((Conn#connect.log_fun), debug, "fetch ~p", [Query1]),
    Packet =  <<?MYSQL_QUERY_OP, Query1/binary>>,
    case do_send(Conn#connect{ seqnum = 0}, Packet) of
	{ok, Conn2} ->
	    get_query_response(Conn2);
	{error, Code, Reason} ->
	    Msg = io_lib:format("Failed sending data "
			"on socket: ~w: ~p",
			[Code, Reason]),
	    {error, Code, Msg}
    end.

do_query_without_retrieve_rows(Conn, Query) when is_record(Conn, connect) ->
    Query1 = iolist_to_binary(Query),
    ?Log2((Conn#connect.log_fun), debug, "fetch ~p", [Query1]),
    Packet =  <<?MYSQL_QUERY_OP, Query1/binary>>,
    case do_send(Conn#connect{ seqnum = 0}, Packet) of
	{ok, Conn2} ->
	    get_query_response_without_retrieve_rows(Conn2);
	{error, Code, Reason} ->
	    Msg = io_lib:format("Failed sending data "
			"on socket: ~w: ~p",
			[Code, Reason]),
	    {error, Code, Msg}
    end;
do_query_without_retrieve_rows(Conn, _Query) ->
	exit(io_lib:format("[~w] Conn is not record #connect: ~p~n", [self(), Conn])).

do_queries(Conn, Queries) when not is_list(Queries) ->
	do_query(Conn, Queries);

%% Execute a list of queries, returning the response for the last query.
%% If a query returns an error before the last query is executed, the
%% loop is aborted and the error is returned.
do_queries(Conn, Queries) ->
    %catch
	lists:foldl(
	  fun(Query, IConn) ->
		  case do_query(IConn, Query) of
		      {error, _} = Err -> throw(Err);
		      {data, Conn2, _} -> Conn2;
		      {updated, Conn2, _} -> Conn2
		  end
	  end, Conn, Queries).

%%--------------------------------------------------------------------
%% Function: get_query_response(LogFun, RecvPid)
%%           LogFun  = undefined | function() with arity 3
%%           RecvPid = pid(), mysql_recv process
%%           Version = integer(), Representing MySQL version used
%% Descrip.: Wait for frames until we have a complete query response.
%% Returns :   {data, #mysql_result}
%%             {updated, #mysql_result}
%%             {error, Code, #mysql_result}
%%           FieldInfo    = list() of term()
%%           Rows         = list() of [string()]
%%           AffectedRows = int()
%%           Reason       = term()
%%--------------------------------------------------------------------
get_query_response(Conn) ->
    ?Log2((Conn#connect.log_fun), debug, "get_query_response. connect: ~p", [Conn]),
    case do_recv(Conn) of
	{ok, Conn2, Packet} ->
	    {Fieldcount, Rest} = get_lcb(Packet),
	    case Fieldcount of
		0 ->
		    %% No Tabular data
		    {AffectedRows, Rest2} = get_lcb(Rest),
		    {InsertId, _} = get_lcb(Rest2),
		    {updated, Conn2,
				#mysql_result{affectedrows=AffectedRows, insertid=InsertId}};
		255 ->
		    <<Code:16/little, Message/binary>>  = Rest,
		    {query_error, Conn2, Code, #mysql_result{error=Message}};
		_ ->
		    %% Tabular data received
		    case get_fields(Conn2, []) of
			{ok, Conn3, Fields} ->
				?Log2((Conn#connect.log_fun), debug, "get_query_response. fields: ~p~nConnect: ~p", [Fields, Conn3]),

			    case get_rows(Fields, Conn3, []) of
				{ok, Conn4, Rows} ->
					?Log2((Conn#connect.log_fun), debug, "get_query_response. Rows: ~p~nConnect: ~p", [Rows, Conn4]),
				    {data, Conn4, #mysql_result{fieldinfo=Fields, rows=Rows}};
				{error, Code, Reason} ->
				    {error, Code, #mysql_result{error=Reason}}
			    end;
			{error, Code, Reason} ->
			    {error, Code, #mysql_result{error=Reason}}
		    end
	    end;
	{error, Code, Reason} ->
	    {error, Code, #mysql_result{error=Reason}}
    end.

get_query_response_without_retrieve_rows(Conn) ->
    ?Log2((Conn#connect.log_fun), debug, "get_query_response. connect: ~p", [Conn]),
    case do_recv(Conn) of
	{ok, Conn2, Packet} ->
	    {Fieldcount, Rest} = get_lcb(Packet),
	    case Fieldcount of
		0 ->
		    %% No Tabular data
		    {AffectedRows, Rest2} = get_lcb(Rest),
		    {InsertId, _} = get_lcb(Rest2),
		    {updated, Conn2,
				#mysql_result{affectedrows=AffectedRows, insertid=InsertId}};
		255 ->
		    <<Code:16/little, Message/binary>>  = Rest,
		    {query_error, Conn2, Code, #mysql_result{error=Message}};
		_ ->
		    %% Tabular data received
		    case get_fields(Conn2, []) of
			{ok, Conn3, Fields} ->
			    case retrieve_rows(Fields, Conn3) of
				{ok, Conn4} ->
					{empty_data, Conn4};
				    %{data, Conn4, #mysql_result{fieldinfo=Fields, rows=Rows}};
				{error, Code, Reason} ->
				    {error, Code, #mysql_result{error=Reason}}
			    end;
			{error, Code, Reason} ->
			    {error, Code, #mysql_result{error=Reason}}
		    end
	    end;
	{error, Code, Reason} ->
	    {error, Code, #mysql_result{error=Reason}}
    end.

%%--------------------------------------------------------------------
%% Function: get_fields(LogFun, RecvPid, [], Version)
%%           LogFun  = undefined | function() with arity 3
%%           RecvPid = pid(), mysql_recv process
%%           Version = integer(), Representing MySQL version used
%% Descrip.: Received and decode field information.
%% Returns : {ok, FieldInfo} |
%%           {error, Reason}
%%           FieldInfo = list() of term()
%%           Reason    = term()
%%--------------------------------------------------------------------
%% Support for MySQL 4.0.x:
get_fields(Conn, Res) when Conn#connect.mysql_version == ?MYSQL_4_0 ->
    case do_recv(Conn) of
	{ok, Conn2, Packet} ->
	    case Packet of
		<<254:8>> ->
		    {ok, Conn2, lists:reverse(Res)};
		<<254:8, Rest/binary>> when size(Rest) < 8 ->
		    {ok, Conn2, lists:reverse(Res)};
		_ ->
		    {Table, Rest} = get_with_length(Packet),
		    {Field, Rest2} = get_with_length(Rest),
		    {LengthB, Rest3} = get_with_length(Rest2),
		    LengthL = size(LengthB) * 8,
		    <<Length:LengthL/little>> = LengthB,
		    {Type, Rest4} = get_with_length(Rest3),
		    {_Flags, _Rest5} = get_with_length(Rest4),
		    This = {Table,
			    Field,
			    Length,
			    %% TODO: Check on MySQL 4.0 if types are specified
			    %%       using the same 4.1 formalism and could
			    %%       be expanded to atoms:
			    Type},
		    get_fields(Conn2, [This | Res])
	    end;
	Error -> Error
    end;
%% Support for MySQL 4.1.x and 5.x:
get_fields(Conn, Res) when Conn#connect.mysql_version == ?MYSQL_4_1 ->
    case do_recv(Conn) of
	{ok, Conn2, Packet} ->
	    case Packet of
		<<254:8>> ->
		    {ok, Conn2, lists:reverse(Res)};
		<<254:8, Rest/binary>> when size(Rest) < 8 ->
		    {ok, Conn2, lists:reverse(Res)};
		_ ->
		    {_Catalog, Rest} = get_with_length(Packet),
		    {_Database, Rest2} = get_with_length(Rest),
		    {Table, Rest3} = get_with_length(Rest2),
		    %% OrgTable is the real table name if Table is an alias
		    {_OrgTable, Rest4} = get_with_length(Rest3),
		    {Field, Rest5} = get_with_length(Rest4),
		    %% OrgField is the real field name if Field is an alias
		    {_OrgField, Rest6} = get_with_length(Rest5),

		    <<_Metadata:8/little, _Charset:16/little,
		     Length:32/little, Type:8/little,
		     _Flags:16/little, _Decimals:8/little,
		     _Rest7/binary>> = Rest6,

		    This = {Table,
			    Field,
			    Length,
			    get_field_datatype(Type)},
		    get_fields(Conn2, [This | Res])
	    end;
	Error -> Error
    end.

%%--------------------------------------------------------------------
%% Function: get_rows(N, LogFun, RecvPid, [])
%%           N       = integer(), number of rows to get
%%           LogFun  = undefined | function() with arity 3
%%           RecvPid = pid(), mysql_recv process
%% Descrip.: Receive and decode a number of rows.
%% Returns : {ok, Rows} |
%%           {error, Reason}
%%           Rows = list() of [string()]
%%--------------------------------------------------------------------
get_rows(Fields, Conn, Res) ->
    case do_recv(Conn) of
	{ok, Conn2, Packet} ->
	    case Packet of
		<<254:8, Rest/binary>> when size(Rest) < 8 ->
		    {ok, Conn2, lists:reverse(Res)};
		_ ->
		    {ok, This} = get_row(Fields, Packet, []),
		    get_rows(Fields, Conn2, [This | Res])
	    end;
	Error -> Error
    end.

% retrieve but do not return rows
retrieve_rows(Fields, Conn) ->
    case do_recv(Conn) of
	{ok, Conn2, Packet} ->
	    case Packet of
		<<254:8, Rest/binary>> when size(Rest) < 8 ->
		    {ok, Conn2};
		_ ->
		    {ok, _This} = get_row(Fields, Packet, []),
		    retrieve_rows(Fields, Conn2)
	    end;
	Error -> Error
    end.

%% part of get_rows/4
get_row([], _Data, Res) ->
    {ok, lists:reverse(Res)};
get_row([Field | OtherFields], Data, Res) ->
    {Col, Rest} = get_with_length(Data),
    This = case Col of
	       null ->
		   undefined;
	       _ ->
		   convert_type(Col, element(4, Field))
	   end,
    get_row(OtherFields, Rest, [This | Res]).

get_with_length(Bin) when is_binary(Bin) ->
    case get_lcb(Bin) of
    {null, Rest} -> {null, Rest};
    {Length, Rest} -> split_binary(Rest, Length)
    end.

get_lcb(<<251:8, Rest/binary>>) ->
    {null, Rest};
get_lcb(<<252:8, Value:16/little, Rest/binary>>) ->
    {Value, Rest};
get_lcb(<<253:8, Value:24/little, Rest/binary>>) ->
    {Value, Rest};
get_lcb(<<254:8, Value:32/little, Rest/binary>>) ->
    {Value, Rest};
get_lcb(<<Value:8, Rest/binary>>) when Value < 251 ->
    {Value, Rest};
get_lcb(<<255:8, Rest/binary>>) ->
    {255, Rest}.


%%--------------------------------------------------------------------
%% Function: normalize_version(Version, LogFun)
%%           Version  = string()
%%           LogFun   = undefined | function() with arity 3
%% Descrip.: Return a flag corresponding to the MySQL version used.
%%           The protocol used depends on this flag.
%% Returns : Version = string()
%%--------------------------------------------------------------------
normalize_version([$4,$.,$0|_T], LogFun) ->
    ?Log(LogFun, debug, "switching to MySQL 4.0.x protocol."),
    ?MYSQL_4_0;
normalize_version([$4,$.,$1|_T], _LogFun) ->
    ?MYSQL_4_1;
normalize_version([$5|_T], _LogFun) ->
    %% MySQL version 5.x protocol is compliant with MySQL 4.1.x:
    ?MYSQL_4_1;
normalize_version(_Other, LogFun) ->
    ?Log(LogFun, error, "MySQL version not supported: MySQL Erlang module "
	 "might not work correctly."),
    %% Error, but trying the oldest protocol anyway:
    ?MYSQL_4_0.



%%--------------------------------------------------------------------
%% Function: get_field_datatype(DataType)
%%           DataType = integer(), MySQL datatype
%% Descrip.: Return MySQL field datatype as description string
%% Returns : String, MySQL datatype
%%--------------------------------------------------------------------
get_field_datatype(0) ->   'DECIMAL';
get_field_datatype(1) ->   'TINY';
get_field_datatype(2) ->   'SHORT';
get_field_datatype(3) ->   'LONG';
get_field_datatype(4) ->   'FLOAT';
get_field_datatype(5) ->   'DOUBLE';
get_field_datatype(6) ->   'NULL';
get_field_datatype(7) ->   'TIMESTAMP';
get_field_datatype(8) ->   'LONGLONG';
get_field_datatype(9) ->   'INT24';
get_field_datatype(10) ->  'DATE';
get_field_datatype(11) ->  'TIME';
get_field_datatype(12) ->  'DATETIME';
get_field_datatype(13) ->  'YEAR';
get_field_datatype(14) ->  'NEWDATE';
get_field_datatype(246) -> 'NEWDECIMAL';
get_field_datatype(247) -> 'ENUM';
get_field_datatype(248) -> 'SET';
get_field_datatype(249) -> 'TINYBLOB';
get_field_datatype(250) -> 'MEDIUM_BLOG';
get_field_datatype(251) -> 'LONG_BLOG';
get_field_datatype(252) -> 'BLOB';
get_field_datatype(253) -> 'VAR_STRING';
get_field_datatype(254) -> 'STRING';
get_field_datatype(255) -> 'GEOMETRY'.

convert_type(Val, ColType) ->
    case ColType of
	T when T == 'TINY';
	       T == 'SHORT';
	       T == 'LONG';
	       T == 'LONGLONG';
	       T == 'INT24';
	       T == 'YEAR' ->
	    list_to_integer(binary_to_list(Val));
	T when T == 'TIMESTAMP';
	       T == 'DATETIME' ->
	    {ok, [Year, Month, Day, Hour, Minute, Second], _Leftovers} =
		io_lib:fread("~d-~d-~d ~d:~d:~d", binary_to_list(Val)),
	    {datetime, {{Year, Month, Day}, {Hour, Minute, Second}}};
	'TIME' ->
	    {ok, [Hour, Minute, Second], _Leftovers} =
		io_lib:fread("~d:~d:~d", binary_to_list(Val)),
	    {time, {Hour, Minute, Second}};
	'DATE' ->
	    {ok, [Year, Month, Day], _Leftovers} =
		io_lib:fread("~d-~d-~d", binary_to_list(Val)),
	    {date, {Year, Month, Day}};
	T when T == 'DECIMAL';
	       T == 'NEWDECIMAL';
	       T == 'FLOAT';
	       T == 'DOUBLE' ->
	    {ok, [Num], _Leftovers} =
		case io_lib:fread("~f", binary_to_list(Val)) of
		    {error, _} ->
			io_lib:fread("~d", binary_to_list(Val));
		    Res ->
			Res
		end,
	    Num;
	_Other ->
	    Val
    end.

