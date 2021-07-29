# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
from unittest.mock import patch

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        from wazuh.core import syscheck


@pytest.mark.parametrize('agent', ['001', '002', '003'])
@patch('wazuh.core.wdb.WazuhDBConnection')
def test_syscheck_delete_agent(mock_db_conn, agent):
    """Test if proper parameters are being sent to the wdb socket.

    Parameters
    ----------
    agent : str
        Agent whose information is being deleted from the db.
    mock_db_conn : WazuhDBConnection
        Object used to send the delete message to the wazuhdb socket.
    """
    syscheck.syscheck_delete_agent(agent, mock_db_conn)
    mock_db_conn.execute.assert_any_call(f"agent {agent} sql delete from fim_entry", delete=True)
    mock_db_conn.execute.assert_any_call(f"agent {agent} sql update metadata set value = '000' "
                                         "where key like 'fim_db%'", update=True)
    mock_db_conn.execute.assert_called_with(f"agent {agent} sql update metadata set value = '000' "
                                            "where key = 'syscheck-db-completed'", update=True)
