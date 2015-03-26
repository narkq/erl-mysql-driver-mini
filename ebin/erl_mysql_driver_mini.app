{application,erl_mysql_driver_mini,
             [{description,"Minimal MySQL client."},
              {vsn,"1"},
              {modules,[mylib,mysql_sync_auth,mysql_sync_conn,
                        mysql_sync_recv]},
              {registered,[]},
              {applications,[kernel,stdlib]},
              {env,[]}]}.
