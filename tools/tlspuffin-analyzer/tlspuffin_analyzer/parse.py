from binascii import hexlify
from io import BytesIO
from itertools import groupby
from operator import itemgetter

import paramiko as paramiko
from jsonslicer import JsonSlicer


def agent_auth(transport, username):
    """
    Attempt to authenticate to the given transport using any of the private
    keys available from an SSH agent.
    """

    agent = paramiko.Agent()
    agent_keys = agent.get_keys()
    if len(agent_keys) == 0:
        return

    for key in agent_keys:
        print("Trying ssh-agent key %s" % hexlify(key.get_fingerprint()))
        try:
            transport.auth_publickey(username, key)
            print("... success!")
            return
        except paramiko.SSHException:
            print("... nope.")


def load_json_slurpy_ssh(host, base_path, experiment, worker_id, user="mammann"):
    t = paramiko.Transport((host, 22))
    t.use_compression(True)
    t.start_client()
    agent_auth(t, user)

    sftp = paramiko.SFTPClient.from_transport(t)

    file = sftp.open("%s/experiments/%s/stats.json" % (base_path, experiment), "r")
    file.prefetch()
    data = file.read()

    return list(filter_by_id(JsonSlicer(BytesIO(data), (), yajl_allow_multiple_values=True, yajl_allow_partial_values=True), worker_id))


def load_json_slurpy(json_path, worker_id):
    with open(json_path) as stats:
        return list(filter_by_id(
            JsonSlicer(stats, (), yajl_allow_multiple_values=True, yajl_allow_partial_values=True),
            worker_id)
        )


def group_by_id(all_stats):
    sortkeyfn = itemgetter("id")
    return map(lambda t: t[1], groupby(sorted(all_stats, key=sortkeyfn), key=sortkeyfn))


def filter_by_id(all_stats, id):
    return [item for item in all_stats if item["id"] == id]
