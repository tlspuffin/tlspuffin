"""Tests of the SSH triage scripts: they parse, they name only symbols of sshpuffin's signature,
their constants are the Rust ones, the bucket table is well formed, and the root-cause key follows
the rules ssh_rootcause.py documents.

The objectives below are written by hand in the format of sshpuffin's replays (recipes as the
pretty-printer writes them, claims, decrypted transcripts, precomputation values).

From the repository root, with the standard library only:
    python3 -B -m unittest discover -s evaluation-ddyf/ssh -p 'test_*.py'
"""

import ast
import importlib.util
import re
import sys
import unittest
from pathlib import Path

EVALUATION = Path(__file__).resolve().parents[1]
SSH_SRC = EVALUATION.parent / "sshpuffin" / "src"


def _load():
    """The scripts, with evaluation-ddyf loaded as the package evaluation_ddyf (the name of the
    directory is not an identifier)."""
    if "evaluation_ddyf" not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            "evaluation_ddyf", EVALUATION / "__init__.py", submodule_search_locations=[str(EVALUATION)]
        )
        package = importlib.util.module_from_spec(spec)
        sys.modules["evaluation_ddyf"] = package
        spec.loader.exec_module(package)
    from evaluation_ddyf.ssh import gen_rootcause_table, rootcause_table, ssh_rootcause

    return ssh_rootcause, rootcause_table, gen_rootcause_table


rc, table, gen = _load()


# ---------------------------------------------------------------- the Rust sources
def signature():
    """The symbols of SSH_SIGNATURE (the define_signature! of sshpuffin/src/ssh/mod.rs)."""
    text = (SSH_SRC / "ssh" / "mod.rs").read_text()
    start = text.index("define_signature!(")
    return set(re.findall(r"\b(fn_[a-z0-9_]+)\b", text[start : text.index("\n);", start)]))


def rust_int(expr):
    """The value of a constant Rust integer expression (literals, u32::MAX, + - *)."""

    def value(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult)):
            a, b = value(node.left), value(node.right)
            return {ast.Add: a + b, ast.Sub: a - b, ast.Mult: a * b}[type(node.op)]
        raise ValueError(f"not a constant expression: {expr}")

    return value(ast.parse(expr.replace("u32::MAX", "0xFFFFFFFF"), mode="eval").body)


def u32_atoms():
    """{name: the expression it returns} of every nullary `-> Result<u32, FnError>` function."""
    out = {}
    for path in sorted(SSH_SRC.rglob("*.rs")):
        for name, body in re.findall(
            r"pub fn (fn_[a-z0-9_]+)\(\)\s*->\s*Result<u32,\s*FnError>\s*\{(.*?)\n\}", path.read_text(), re.S
        ):
            body = re.sub(r"//[^\n]*", "", body)
            out[name] = re.fullmatch(r"\s*Ok\((.*)\)\s*", body, re.S).group(1)
    return out


# ---------------------------------------------------------------- objectives, written by hand
def t(name, *args, typ="T"):
    """A term as sshpuffin's pretty-printer writes it."""
    if not args:
        return f"{name} -> {typ}"
    inner = ",\n".join("\t" + a.replace("\n", "\n\t") for a in args)
    return f"{name}(\n{inner}\n) -> {typ}"


def var(label, n=0, typ="SshBytes"):
    """The variable of a sealed step for the n-th value bound to `label`."""
    return f'(Some(Label(Some("{label}"))), {n})[None]/{typ}'


PEER_PUBLIC_KEY = "(Some(Agent(AgentName(0))), 0)[None]/SshBytes"  # a query of the PUT's KEX reply
SHARED_SECRET = t("fn_ecdh_shared_secret", t("fn_client_ecdh_privkey"), PEER_PUBLIC_KEY)
# H = hash(V_C, V_S, I_C, I_S, K_S, Q_C, Q_S, K): only its 8th input, K, matters to the classifier
EXCHANGE_HASH = t("fn_kex_exchange_hash", *[t(f"fn_input_{i}") for i in range(7)], var("shared_secret_0@0"))
DERIVATION_INPUTS = (var("shared_secret_0@0"), var("exchange_hash_0@0"), var("session_id@0"))
SCHEDULE = [  # the precomputations of a sealed c2s step of the first keys, as the seeds have them
    ("shared_secret_0@0", SHARED_SECRET),
    ("exchange_hash_0@0", EXCHANGE_HASH),
    ("session_id@0", t("fn_session_id_from_hash", var("exchange_hash_0@0"))),
    ("c2s_key_0@0", t("fn_derive_aes_key_c2s", *DERIVATION_INPUTS)),
    ("c2s_iv_0@0", t("fn_derive_iv_c2s", *DERIVATION_INPUTS)),
]
NEWKEYS = t("fn_packet", t("fn_new_keys"))
SERVICE_REQUEST = t("fn_service_request", t("fn_ssh_userauth"))
PASSWORD = t("fn_password_auth_data", t("fn_password"))
USER_SERVICE_METHOD = (t("fn_username"), t("fn_ssh_connection"), t("fn_method_password"))
USERAUTH_REQUEST = t("fn_user_auth_request", *USER_SERVICE_METHOD, PASSWORD)


def sealed(message, counter="fn_u32_auto", key=None, iv=None):
    return t("fn_encrypt_packet_aesgcm", message, key or var("c2s_key_0@0"), iv or var("c2s_iv_0@0"), t(counter))


def sent(n, recipe, precomputations=(), claims=()):
    action = {"Input": {"recipe": recipe, "raw": None, "precomputations": [list(p) for p in precomputations]}}
    return {"step_number": n, "agent": 0, "action": action, "claims": list(claims), "knowledges": []}


def received(n, claims=()):
    return {"step_number": n, "agent": 0, "action": "Output", "claims": list(claims), "knowledges": []}


def claim(auth_method="", session_id=(1, 2, 3), kex=None):
    """A claim as a replay prints it. `kex`: the exchange hashes of the key-exchange secrets it carries,
    one per key exchange (None: a claim from before the claims carried them)."""
    secrets = ""
    if kex is not None:
        entries = (f"KexSecret {{ exchange_hash: [{', '.join(map(str, h))}], shared_secret: [7, 7] }}" for h in kex)
        secrets = f", kex_secrets: [{', '.join(entries)}]"
    return (
        f'SshClaimInner {{ auth_method: "{auth_method}", auth_user: "{"user" if auth_method else ""}", '
        f"auth_key_fp: [], session_id: [{', '.join(map(str, session_id))}]{secrets} }}"
    )


# The precomputations of a sealed step of the keys of a rekey: those of the first keys, then the rekey's own
# (SealKeys::rekey), whose exchange hash is a new one and whose session id stays the first.
REKEY_EXCHANGE_HASH = t("fn_kex_exchange_hash", *[t(f"fn_input_{i}") for i in range(7)], var("shared_secret_1@0"))
REKEY_DERIVATION_INPUTS = (var("shared_secret_1@0"), var("exchange_hash_1@0"), var("session_id@0"))
REKEY_SCHEDULE = SCHEDULE + [
    ("shared_secret_1@0", t("fn_ecdh_shared_secret", t("fn_client_ecdh_privkey"), t("fn_rekey_public_key"))),
    ("exchange_hash_1@0", REKEY_EXCHANGE_HASH),
    ("c2s_key_1@0", t("fn_derive_aes_key_c2s", *REKEY_DERIVATION_INPUTS)),
    ("c2s_iv_1@0", t("fn_derive_iv_c2s", *REKEY_DERIVATION_INPUTS)),
]
GLOBAL_REQUEST = t("fn_global_request", t("fn_request_unknown"), t("fn_true"), t("fn_empty_bytes_vec"))


def sealed_after_rekey(message):
    return sealed(message, key=var("c2s_key_1@0"), iv=var("c2s_iv_1@0"))


def aligned(*keys):
    """The decrypted transcript of a PUT that sent the messages `keys` [(msg_number, ordinal)], in order."""

    def key(m, o):
        return f"AlignmentKey {{ channel: 0, msg_number: {m}, ordinal: {o} }}"

    by_key = ", ".join(f"{key(m, o)}: Message" for m, o in sorted(keys))
    order = ", ".join(key(m, o) for m, o in keys)
    return [{"Label": "Decryption"}, f"AlignedTranscript {{ by_key: {{{by_key}}}, order: [{order}] }}"]


def value(label, data, typ="SessionId"):
    """What a precomputation evaluated to, as a replay lists it."""
    return [{"Label": label}, f"{typ}([{', '.join(map(str, data))}])"]


def replay(steps, role="Server", knowledges=(), error=None):
    agents = [{"name": 0, "protocol_config": {"typ": role}}]
    execution = {
        "agents": agents,
        "steps": steps,
        "extra_knowledges": list(knowledges),
        "executed_until": len(steps) - 1,
    }
    return {"put": "x", "error": error, "execution": execution}


def status_difference(libssh, libssh_steps, wolfssh, wolfssh_steps):
    return {
        "Status": {
            "first_status": libssh,
            "first_executed_steps": libssh_steps,
            "second_status": wolfssh,
            "second_executed_steps": wolfssh_steps,
            "total_step": 8,
        }
    }


class Objective:
    """What the sorter hands the classifier: the differential record and the two per-PUT replays."""

    def __init__(self, libssh, wolfssh, errors=()):
        self._libssh, self._wolfssh, self.errors, self.filepath = libssh, wolfssh, list(errors), "objective"

    def put1(self):
        return self._libssh

    def put2(self):
        return self._wolfssh


AEAD_TAG = "Unknown error code (rc=-1001 gerr=-180)"


# ---------------------------------------------------------------- the scripts against the sources
class Sources(unittest.TestCase):
    def test_every_script_compiles(self):
        for path in sorted(EVALUATION.rglob("*.py")):
            with self.subTest(script=str(path.relative_to(EVALUATION))):
                compile(path.read_text(), str(path), "exec")

    def test_the_scripts_name_only_symbols_of_the_signature(self):
        symbols = signature()
        for path in sorted((EVALUATION / "ssh").glob("*.py")):
            if path.name.startswith("test_"):
                continue
            tree = ast.parse(path.read_text())
            prefixes = {  # the strings handed to str.startswith: prefixes of symbols
                id(c)
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "startswith"
                for arg in node.args
                for c in ast.walk(arg)
            }
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                    continue
                if not re.fullmatch(r"fn_[a-z0-9_]+", node.value):
                    continue
                with self.subTest(script=path.name, symbol=node.value):
                    if id(node) in prefixes:
                        self.assertTrue(any(s.startswith(node.value) for s in symbols))
                    else:
                        self.assertIn(node.value, symbols)

    def test_the_u32_constants_are_the_rust_ones(self):
        symbols = signature()
        atoms = {name: expr for name, expr in u32_atoms().items() if name in symbols}
        literals = {name for name in atoms if re.fullmatch(r"fn_u32_\d+", name)}
        for name in sorted(literals):
            self.assertEqual(rust_int(atoms[name]), int(name[len("fn_u32_") :]), name)
        self.assertEqual(atoms["fn_u32_auto"], "U32_AUTO_SENTINEL")
        constants = (SSH_SRC / "ssh" / "fn_constants.rs").read_text()
        sentinel = re.search(r"pub const U32_AUTO_SENTINEL: u32 = ([^;]+);", constants).group(1)
        self.assertEqual(rc.U32_AUTO_SENTINEL, rust_int(sentinel))
        others = {name: expr for name, expr in atoms.items() if name not in literals and name != "fn_u32_auto"}
        self.assertEqual(rc._U32_CONST, {name: rust_int(expr) for name, expr in others.items()})


class Table(unittest.TestCase):
    # the tags of gen_rootcause_table, and any other the table's legend defines (--templated-tag)
    TAGS = set(gen.TAGS) | set(re.findall(r"^  ([A-Z][A-Z-]+) ", table.__doc__ or "", re.M))
    KEY = re.compile(
        r"named:[a-z0-9_]+|auth_unexplained:(server|client)|aead:(server|client):[a-z_]+(:unconfirmed)?"
        r"|status:(server|client):([LW]|=):.+|claim:(server|client):[LW]:.+|shape:(server|client):.+"
    )

    def test_the_rows_are_well_formed(self):
        names, keys = set(), set()
        for row in table.ROWS:
            with self.subTest(row=row[0]):
                self.assertEqual(len(row), 5)
                name, key, tag, explanation, count = row
                self.assertRegex(name, r"^[a-z0-9_]+$")  # a directory name
                self.assertNotIn(name, names)
                self.assertNotIn(key, keys)
                self.assertTrue(self.KEY.fullmatch(key), key)
                self.assertIn(tag, self.TAGS)
                self.assertTrue(isinstance(explanation, str) and explanation)
                self.assertTrue(isinstance(count, int) and count >= 0)
                names.add(name)
                keys.add(key)


# ---------------------------------------------------------------- the classifier
class Generation(unittest.TestCase):
    """gen_rootcause_table on a census written by hand."""

    @staticmethod
    def census(*keys, **statuses):
        rows = [{"key": key} for key in keys]
        rows += [{"key": None, "second_status": status} for status in statuses.get("statuses", ())]
        return rows

    def rows(self, *keys, statuses=()):
        return {row[1]: row for row in gen.Generator(self.census(*keys, statuses=statuses), "UNTRIAGED").rows()}

    def test_every_mechanism_has_an_explanation(self):
        source = (EVALUATION / "ssh" / "ssh_rootcause.py").read_text()
        mechanisms = set()
        for name in re.findall(r'return f?\(?"((?:known|diverge)_[a-z0-9_{}]+)"', source):
            mechanisms |= {name.replace("{r}", role) for role in ("server", "client")}
        mechanisms.add("known_wolfssh_client_accepts_unsolicited_userauth_success_no_request")
        self.assertGreater(len(mechanisms), 15)
        self.assertEqual(sorted(mechanisms - set(gen.NAMED)), [])

    def test_tags_and_names(self):
        rows = self.rows(
            "named:known_wolfssh_unsolicited_service_accept",
            "aead:server:wrong_exchange_hash",
            "aead:server:wrong_exchange_hash:unconfirmed",
            "aead:client:plaintext_after_newkeys:unconfirmed",
            "aead:server:unexplained:unconfirmed",
            "claim:server:W:mapper_unbound_variable",
            "status:client:W:mapper_unbound_variable",
            "status:server:W:wolfssh_gerr1089",
            "status:server:W:wolfssh_gerr1094",
            "status:server:L:libssh_could_not_generate_shared_secret",
            "claim:server:L:success",
            "shape:server:L91.0/W92.0",
            "shape:server:reorder:L100.1/W99.0",
            "shape:server:L50.0/W-",
            "shape:server:L94.1/W96.0",
            "shape:client:rekey_progress",
            "shape:server:C52",
            "shape:server:C94",
            "status:server:=:libssh_received_unexpected_packets_in_strict_kex_mode|wolfssh_gerr1089",
            statuses=["error in PUT : Message ID not allowed (rc=-1001 gerr=-1094)"],
        )
        expected = {
            "named:known_wolfssh_unsolicited_service_accept": ("known_wolfssh_unsolicited_service_accept", "RFC-LOW"),
            "aead:server:wrong_exchange_hash": ("wolfssh_aead_reject_wrong_exchange_hash_server", "KNOWN-CVE"),
            "aead:server:wrong_exchange_hash:unconfirmed": (
                "wolfssh_aead_reject_wrong_exchange_hash_server_unconfirmed", "AUDIT"),
            "aead:client:plaintext_after_newkeys:unconfirmed": (
                "wolfssh_aead_reject_plaintext_after_newkeys_client_unconfirmed", "BENIGN-ARTEFACT"),
            "aead:server:unexplained:unconfirmed": ("wolfssh_aead_reject_unexplained_server_unconfirmed", "AUDIT"),
            # the claim difference of a term-evaluation failure is the apparatus's ...
            "claim:server:W:mapper_unbound_variable": (
                "kex_not_finalised_by_wolfssh_server_mapper_unbound_variable", "HARNESS"),
            # ... while a run that stops on one, where the other's goes on, is a difference of the PUTs
            "status:client:W:mapper_unbound_variable": (
                "wolfssh_client_rejects_first_mapper_unbound_variable", "UNTRIAGED"),
            "status:server:W:wolfssh_gerr1089": ("wolfssh_server_rejects_first_gerr1089_unknown", "RFC-LOW"),
            # wolfSSH's name for the code comes from the census
            "status:server:W:wolfssh_gerr1094": (
                "wolfssh_server_rejects_first_gerr1094_message_id_not_allowed", "UNTRIAGED"),
            "status:server:L:libssh_could_not_generate_shared_secret": (
                "libssh_server_rejects_first_libssh_could_not_generate_shared_secret", "AUDIT"),
            "claim:server:L:success": ("kex_not_finalised_by_libssh_server_success", "UNTRIAGED"),
            "shape:server:L91.0/W92.0": ("transcript_server_first_libssh_91_0_wolfssh_92_0", "AUDIT"),
            "shape:server:reorder:L100.1/W99.0": ("transcript_server_reorder_first_libssh_100_1_wolfssh_99_0", "AUDIT"),
            "shape:server:L50.0/W-": ("transcript_server_first_libssh_50_0_wolfssh_none", "AUDIT"),
            "shape:server:L94.1/W96.0": ("transcript_server_first_libssh_94_1_wolfssh_96_0", "UNTRIAGED"),
            "shape:client:rekey_progress": ("transcript_client_rekey_handshake_progress", "KNOWN-CLASS"),
            "shape:server:C52": ("transcript_server_content_differs_52", "AUDIT"),
            "shape:server:C94": ("transcript_server_content_differs_94", "UNTRIAGED"),
            # both stop at the same step: wolfSSH's non-conformance is not hidden by libssh's benign strict KEX
            "status:server:=:libssh_received_unexpected_packets_in_strict_kex_mode|wolfssh_gerr1089": (
                "both_fail_same_step_server_libssh_libssh_received_unexpected_packets_in_strict_kex_mode"
                "_wolfssh_gerr1089_unknown", "RFC-LOW"),
        }
        self.assertEqual({key: row[0::2][:2] for key, row in rows.items()}, expected)
        self.assertIn("without an error", rows["claim:server:L:success"][3])
        self.assertIn("SERVICE_ACCEPT", self.rows("shape:server:L6.0/W-")["shape:server:L6.0/W-"][3])
        self.assertIn("transport generic", self.rows("shape:server:L6.0/W-")["shape:server:L6.0/W-"][3])

    def test_a_shape_after_a_rekey_names_its_key_epoch(self):
        rows = self.rows("shape:server:L-/W7.0@e2", "shape:client:L91.0@e3/W92.0@e3", "shape:server:C91@e2")
        self.assertEqual(rows["shape:server:L-/W7.0@e2"][0], "transcript_server_first_libssh_none_wolfssh_7_0_epoch2")
        self.assertIn("after its first rekey (key epoch 2)", rows["shape:server:L-/W7.0@e2"][3])
        self.assertEqual(rows["shape:client:L91.0@e3/W92.0@e3"][0],
                         "transcript_client_first_libssh_91_0_epoch3_wolfssh_92_0_epoch3")
        self.assertIn("after 2 rekeys (key epoch 3)", rows["shape:client:L91.0@e3/W92.0@e3"][3])
        self.assertEqual(rows["shape:server:C91@e2"][0], "transcript_server_content_differs_91_epoch2")
        self.assertIn("after its first rekey (key epoch 2)", rows["shape:server:C91@e2"][3])

    def test_a_key_without_an_explanation_stops_the_generation(self):
        with self.assertRaises(KeyError):
            self.rows("named:known_something_new")
        with self.assertRaises(KeyError):
            self.rows("aead:server:a_new_cause")

    def test_the_rendered_table(self):
        census = self.census("named:known_wolfssh_unsolicited_service_accept", "shape:server:L94.1/W96.0",
                             "shape:server:L94.1/W96.0", "status:server:W:wolfssh_gerr1094")
        census.append({"key": None})
        generator = gen.Generator(census, "UNTRIAGED", minimum=2)
        module = {}
        exec(gen.render(generator.rows(), "a test census", "UNTRIAGED", 2, generator.residual), module)
        rows = module["ROWS"]
        # the status key of 1 objective is below --min; the named one never is
        self.assertEqual([(r[1], r[4]) for r in rows], [("shape:server:L94.1/W96.0", 2),
                                                        ("named:known_wolfssh_unsolicited_service_accept", 1)])
        self.assertIn("UNTRIAGED", module["__doc__"])
        self.assertIn("1 objectives without a key", module["__doc__"])
        self.assertTrue(all(Table.KEY.fullmatch(r[1]) for r in rows))


class Errors(unittest.TestCase):
    def test_the_wolfssh_code_is_the_cause(self):
        self.assertEqual(rc.wolfssh_code("RSA buffer error (rc=-1001 gerr=-1018)"), -1018)
        # a return code other than WS_FATAL_ERROR is the cause itself: gerr may be an earlier call's
        self.assertEqual(rc.wolfssh_code("Invalid state (rc=-1030 gerr=-1036)"), -1030)
        self.assertEqual(rc.wolfssh_code("DONE/ERROR gerr=-1089"), -1089)
        self.assertIsNone(rc.wolfssh_code("Failed to verify server hostkey signature"))
        self.assertIsNone(rc.wolfssh_code(None))

    def test_error_classes(self):
        cases = {
            None: "success",
            "Success": "success",
            AEAD_TAG: "wolfssh_gerr180",
            "Invalid state (rc=-1030 gerr=-1036)": "wolfssh_gerr1030",
            "SESSION_ERROR: Packet filter: rejected packet type 94": "libssh_packet_filter",
            "error in PUT : SESSION_ERROR: Packet len too high (35000 > 262144)": "libssh_packet_len_too_high",
            "SESSION_ERROR: Socket error: File exists": "libssh_socket_error",
            "Socket error: disconnected": "libssh_socket_error_disconnected",
            # the whole message, without its values
            "SESSION_ERROR: Invalid padding: 200 (12 left)": "libssh_invalid_padding",
            "Receiving banner: too large banner": "libssh_receiving_banner_too_large_banner",
            "Failed to verify server hostkey signature": "libssh_failed_to_verify_server_hostkey_signature",
            "SESSION_ERROR: ": "libssh_empty_error",
            "error executing a function symbol: rustls: no message 5": "mapper_no_message",
            "error evaluating a term": "mapper_unbound_variable",
        }
        for err, cls in cases.items():
            with self.subTest(err=err):
                self.assertEqual(rc.error_class(err), cls)
        # two banner checks are two classes, not one "Receiving banner" prefix
        self.assertNotEqual(
            rc.error_class("Receiving banner: too large banner"), rc.error_class("Receiving banner: bad version")
        )


class Recipes(unittest.TestCase):
    def test_a_sealed_step_reads_through_its_precomputations(self):
        other_key = t("fn_derive_aes_key_c2s", t("fn_other"), *DERIVATION_INPUTS[1:])
        status = replay(
            [
                received(0),
                sent(1, NEWKEYS),
                sent(2, sealed(SERVICE_REQUEST), precomputations=SCHEDULE),
                # binds the key label again: (c2s_key_0@0, 1) is this binding, (.., 0) still the first
                sent(3, sealed(USERAUTH_REQUEST, key=var("c2s_key_0@0", 1)), [("c2s_key_0@0", other_key)]),
            ]
        )
        steps = {i: node for i, node, _ in rc.inputs(status)}
        self.assertEqual(sorted(steps), [1, 2, 3])
        key = steps[2].children[1]
        self.assertEqual((key.name, key.label), ("fn_derive_aes_key_c2s", ("c2s_key_0@0", 0)))
        exchange_hash = key.children[1]
        self.assertEqual(exchange_hash.name, "fn_kex_exchange_hash")
        self.assertEqual(exchange_hash.label, ("exchange_hash_0@0", 0))
        # the shared secret inside the exchange hash is bound too
        self.assertEqual(exchange_hash.children[7].name, "fn_ecdh_shared_secret")
        rebound = steps[3].children[1]
        self.assertEqual((rebound.label, rebound.children[0].name), (("c2s_key_0@0", 1), "fn_other"))
        self.assertEqual(rc.message_of(steps[3]), "fn_user_auth_request")

    def test_counter_values(self):
        def counter(text):
            return rc._counter_value(rc.parse_term(text))

        self.assertEqual(counter(t("fn_u32_3")), 3)
        self.assertEqual(counter(t("fn_port_ssh")), 22)
        self.assertEqual(counter(t("fn_window_size_default")), 2 * 1024 * 1024)
        self.assertEqual(counter(t("fn_extended_data_stderr")), 1)
        self.assertIsNone(counter(t("fn_u32_auto")))  # renumbered
        self.assertEqual(rc._counter_value(rc.parse_term(t("fn_u32_auto")), nested=True), rc.U32_AUTO_SENTINEL)
        window, packet = t("fn_u32_auto"), t("fn_max_packet_size_default")
        session, channel, data = t("fn_channel_session"), t("fn_channel_id_0"), t("fn_empty_bytes_vec")
        open_ = t("fn_channel_open", session, channel, window, packet, data)
        # the sentinel inside a computed counter is not renumbered: its own value is used
        self.assertEqual(counter(t("fn_initial_window_size", open_)), rc.U32_AUTO_SENTINEL)
        open_ = open_.replace("fn_u32_auto", "fn_window_size_default")
        self.assertEqual(counter(t("fn_channel_send_budget", open_)), 32 * 1024)
        queried = t("fn_decrypted_message", "(Some(Agent(AgentName(0))), 3)[None]/RawSshMessageFlight")
        self.assertIsNone(counter(t("fn_channel_send_budget", queried)))

    def test_the_sentinel_is_renumbered_only_on_the_first_16_packets(self):
        steps = [received(0), sent(1, NEWKEYS)] + [sent(2 + i, sealed(SERVICE_REQUEST)) for i in range(17)]
        steps[5] = sent(5, sealed(SERVICE_REQUEST, counter="fn_u32_3"))  # its index: right
        steps[6] = sent(6, sealed(SERVICE_REQUEST, counter="fn_u32_3"))  # index 4: wrong
        steps[7] = sent(7, sealed(SERVICE_REQUEST, counter="fn_port_ssh"))
        objective = Objective(replay(steps), replay(steps))
        inp = rc.inputs(objective.put1())
        self.assertEqual(rc.true_counters(objective.put1())[17], 15)
        self.assertEqual(rc.counter_verdict(objective, inp, 17), "ok")
        self.assertEqual(rc.counter_verdict(objective, inp, 18), "wrong")  # index 16: no atom for it
        self.assertEqual(rc.counter_verdict(objective, inp, 5), "ok")
        self.assertEqual(rc.counter_verdict(objective, inp, 6), "wrong")
        self.assertEqual(rc.counter_verdict(objective, inp, 7), "wrong")


class Shapes(unittest.TestCase):
    def shape(self, libssh, wolfssh, errors=()):
        return rc._shape(Objective(replay([], knowledges=[libssh]), replay([], knowledges=[wolfssh]), errors))

    def test_the_first_divergence_keeps_its_ordinals(self):
        second_channel_message = self.shape(aligned((20, 0), (91, 0), (91, 1)), aligned((20, 0), (91, 0), (92, 0)))
        self.assertEqual(second_channel_message, "L91.1/W92.0")
        self.assertEqual(self.shape(aligned((91, 0), (92, 0)), aligned((92, 0), (91, 0))), "reorder:L91.0/W92.0")
        self.assertEqual(self.shape(aligned((20, 0), (93, 0)), aligned((20, 0))), "L93.0/W-")
        self.assertEqual(self.shape(aligned((20, 0), (20, 1)), aligned((20, 0), (94, 0))), "rekey_progress")
        self.assertEqual(self.shape(aligned((50, 0), (50, 1)), aligned((50, 0), (5, 0))), "auth_retry_count")
        diff = "[ByKey([Changed(AlignmentKey { channel: 0, msg_number: 92, ordinal: 0 }, X)])]"
        changed = {"Knowledges": {"InnerDifference": {"diff": diff}}}
        self.assertEqual(self.shape(aligned((20, 0), (92, 0)), aligned((20, 0), (92, 0)), [changed]), "C92")
        self.assertEqual(rc._shape(Objective(replay([]), replay([]))), "no_transcript")

    def test_a_message_after_a_rekey_carries_its_key_epoch(self):
        """The first EXT_INFO of a PUT that sends it only after a rekey is 7.0, as the EXT_INFO of the first
        keys would be: its key epoch tells them apart."""
        kex, rekey = [(20, 0), (31, 0), (21, 0)], [(20, 1), (31, 1), (21, 1)]
        libssh, wolfssh = aligned(*kex, (6, 0), *rekey), aligned(*kex, (6, 0), *rekey, (7, 0))
        self.assertEqual(self.shape(libssh, wolfssh), "L-/W7.0@e2")
        # the same message under the first keys keeps its key
        self.assertEqual(self.shape(aligned(*kex, (6, 0)), aligned(*kex, (6, 0), (7, 0))), "L-/W7.0")
        # two rekeys
        rekey2 = [(20, 2), (31, 2), (21, 2)]
        self.assertEqual(self.shape(aligned(*kex, *rekey, *rekey2), aligned(*kex, *rekey, *rekey2, (91, 0))),
                         "L-/W91.0@e3")

    def test_a_content_change_is_keyed_by_the_earliest_changed_message_and_its_epoch(self):
        def changed(*keys):
            key = "AlignmentKey {{ channel: 0, msg_number: {}, ordinal: {} }}"
            ops = ", ".join(f"Changed({key.format(m, o)}, X)" for m, o in keys)
            return {"Knowledges": {"InnerDifference": {"diff": f"[ByKey([{ops}])]"}}}

        kex, rekey = [(20, 0), (31, 0), (21, 0)], [(20, 1), (31, 1), (21, 1)]
        after = aligned(*kex, (6, 0), *rekey, (91, 0))
        self.assertEqual(self.shape(after, after, [changed((91, 0))]), "C91@e2")
        # the earliest changed message itself, not the earliest message of a changed number: 91.0 is not changed
        both = aligned(*kex, (91, 0), (92, 0), (91, 1))
        self.assertEqual(self.shape(both, both, [changed((91, 1), (92, 0))]), "C92")


class Named(unittest.TestCase):
    def test_the_port_echo_is_named_for_any_port_when_it_is_the_only_difference(self):
        def echo(*data):
            response = ", ".join(f"Added({i}, {b})" for i, b in enumerate(data))
            key = "AlignmentKey { channel: 0, msg_number: 81, ordinal: 0 }"
            diff = f"[ByKey([Changed({key}, BothRequestSuccess {{ response_data: [{response}] }})])]"
            return {"Knowledges": {"InnerDifference": {"diff": diff}}}

        def named(*errors):
            objective = Objective(replay([]), replay([]), errors)
            return rc._n_misc(objective, "Server", [], set(), set())

        self.assertEqual(named(echo(0, 0, 0, 22)), "known_wolfssh_1246_fwd_port_echo")
        self.assertEqual(named(echo(0, 0, 31, 144)), "known_wolfssh_1246_fwd_port_echo")  # port 8080
        self.assertIsNone(named(echo(0, 0, 22)))  # not a port
        self.assertIsNone(named(echo(0, 0, 0, 22), status_difference("Success", 8, AEAD_TAG, 5)))

    def test_an_unrecognised_channel_request_answered_success(self):
        def named(request_type):
            data = t("fn_empty_bytes_vec")
            request = sealed(t("fn_channel_request", t("fn_channel_id_0"), t(request_type), t("fn_true"), data))
            steps = [received(0), sent(1, NEWKEYS), sent(2, request, precomputations=SCHEDULE)]
            objective = Objective(
                replay(steps, knowledges=[aligned((91, 0), (100, 0))]),
                replay(steps, knowledges=[aligned((91, 0), (99, 0))]),
            )
            return rc._n_misc(objective, "Server", rc.inputs(objective.put1()), {91, 100}, {91, 99})

        mechanism = "known_wolfssh_unrecognised_channel_request_answered_success"
        self.assertEqual(named("fn_request_unknown"), mechanism)
        self.assertIsNone(named("fn_channel_exec"))

    def test_a_classifier_that_raises_is_recorded_and_not_taken_for_no_mechanism(self):
        def broken(es, rl, inp, tl, tw):
            raise KeyError("steps")

        saved, rc._NAMED = rc._NAMED, [broken]
        try:
            before = len(rc.CLASSIFIER_ERRORS)
            with self.assertRaises(KeyError):
                rc.named_mechanisms(Objective(replay([]), replay([])), "Server", [], set(), set())
            self.assertEqual(rc.CLASSIFIER_ERRORS[before:], [("objective", "broken", "KeyError('steps')")])
        finally:
            rc._NAMED = saved
            del rc.CLASSIFIER_ERRORS[before:]


class AuthUnexplained(unittest.TestCase):
    """libssh authenticates on the first of two USERAUTH_REQUESTs, wolfSSH on neither."""

    def unexplained(self, wolfssh_failed_at):
        steps = [
            received(0),
            sent(1, NEWKEYS),
            sent(2, sealed(SERVICE_REQUEST), precomputations=SCHEDULE),
            sent(3, sealed(USERAUTH_REQUEST), claims=[claim("password")]),
            received(4),
            sent(5, sealed(USERAUTH_REQUEST)),
        ]
        objective = Objective(
            replay(steps, knowledges=[aligned((6, 0), (52, 0))]),
            replay(steps[:4], knowledges=[aligned((6, 0))]),
            [status_difference("Success", 5, "Invalid state (rc=-1030 gerr=-1030)", wolfssh_failed_at)],
        )
        return rc.auth_unexplained(objective, "Server", rc.inputs(objective.put1()), {6, 52}, {6})

    def test_a_side_that_died_before_the_winning_attempt_is_excused(self):
        self.assertFalse(self.unexplained(2))

    def test_a_side_that_died_on_the_winning_attempt_is_not(self):
        # libssh authenticated on the request of step 3; judged by the last request (step 5), wolfSSH
        # would be excused
        self.assertTrue(self.unexplained(3))


class Keys(unittest.TestCase):
    """root_cause_key on whole objectives: a server under attack, NEWKEYS at step 1, then sealed steps."""

    def objective(
        self, steps, libssh, wolfssh, libssh_sent=(6, 52), wolfssh_sent=(6,), wolfssh_values=(), libssh_values=()
    ):
        """libssh's replay runs every step and authenticates at step 3; wolfSSH's stops at step 2,
        having claimed the session id [1, 2, 3] at NEWKEYS."""
        wolfssh_steps = [dict(steps[0]), dict(steps[1], claims=[claim()]), dict(steps[2])]
        return Objective(
            replay(steps, knowledges=[aligned(*[(m, 0) for m in libssh_sent]), *libssh_values]),
            replay(wolfssh_steps, knowledges=[aligned(*[(m, 0) for m in wolfssh_sent]), *wolfssh_values]),
            [status_difference(*libssh, *wolfssh)],
        )

    def steps(self, service_request=None):
        return [
            received(0),
            sent(1, NEWKEYS, claims=[claim()]),
            sent(2, service_request or sealed(SERVICE_REQUEST), precomputations=SCHEDULE),
            sent(3, sealed(USERAUTH_REQUEST), claims=[claim("password")]),
            received(4),
        ]

    def test_a_tag_failure_at_the_same_step_as_libssh_is_an_aead_key(self):
        libssh = ("SESSION_ERROR: Invalid padding: 200 (12 left)", 2)
        objective = self.objective(self.steps(), libssh, (AEAD_TAG, 2), libssh_sent=(6,))
        self.assertEqual(rc.root_cause_key(objective), "aead:server:unexplained:unconfirmed")

    def test_a_later_answered_request_does_not_confirm_a_packet_libssh_can_verify(self):
        """The keys are wrong in wolfSSH's run only: libssh's values are its session id, so the packet
        may verify for libssh, and libssh answering the USERAUTH_REQUEST after it proves nothing."""
        wolfssh = [value("session_id@0", [9, 9, 9])]
        libssh = [value("session_id@0", [1, 2, 3]), value("exchange_hash_0@0", [1, 2, 3], "ExchangeHash")]
        objective = self.objective(self.steps(), ("Success", 4), (AEAD_TAG, 2), (6, 52), (6,), wolfssh, libssh)
        self.assertEqual(rc.root_cause_key(objective), "aead:server:wrong_exchange_hash:unconfirmed")

    def test_aead_causes(self):
        wrong_for_both = ([value("session_id@0", [9, 9, 9])], [value("session_id@0", [8, 8, 8])])
        cases = {
            "plaintext_after_newkeys:unconfirmed": (self.steps(t("fn_packet", SERVICE_REQUEST)), ((), ())),
            "wrong_invocation_counter": (self.steps(sealed(SERVICE_REQUEST, counter="fn_u32_5")), ((), ())),
            # the session id the keys derive from is neither the one wolfSSH claimed nor libssh's
            # ([1, 2, 3] both)
            "wrong_exchange_hash": (self.steps(), wrong_for_both),
            "broken_key_schedule_term": (
                self.steps(sealed(SERVICE_REQUEST, key=t("fn_placeholder_32bytes"))), ((), ())),
        }
        for key, (steps, (wolfssh, libssh)) in cases.items():
            with self.subTest(key=key):
                objective = self.objective(steps, ("Success", 4), (AEAD_TAG, 2), (6, 52), (6,), wolfssh, libssh)
                self.assertEqual(rc.root_cause_key(objective), f"aead:server:{key}")

    def test_the_same_values_are_not_a_wrong_exchange_hash(self):
        values = [value("session_id@0", [1, 2, 3]), value("exchange_hash_0@0", [1, 2, 3], "ExchangeHash")]
        objective = self.objective(self.steps(), ("Success", 4), (AEAD_TAG, 2), wolfssh_values=values)
        self.assertEqual(rc.root_cause_key(objective), "aead:server:unexplained:unconfirmed")

    def test_without_keys_libssh_does_not_confirm_a_wrong_term(self):
        """A wrong counter is wrong in any run, but a libssh that never claimed a session id never
        reached the AES-GCM state: getting past the packet is no acceptance of it."""
        steps = self.steps(sealed(SERVICE_REQUEST, counter="fn_u32_5"))
        steps[1], steps[3] = sent(1, NEWKEYS), sent(3, sealed(USERAUTH_REQUEST))  # libssh's run: no claim
        objective = self.objective(steps, ("Success", 4), (AEAD_TAG, 2), libssh_sent=(6,))
        self.assertEqual(rc.root_cause_key(objective), "aead:server:wrong_invocation_counter:unconfirmed")

    def test_a_packet_mutated_after_the_rejected_one_does_not_make_it_mutated(self):
        """Two packets under the same keys; only the one after wolfSSH failed has another key schedule."""
        other_key = t("fn_derive_aes_key_c2s", t("fn_other"), *DERIVATION_INPUTS[1:])
        steps = self.steps()
        steps[3] = sent(3, sealed(USERAUTH_REQUEST, key=other_key), claims=[claim("password")])
        objective = self.objective(steps, ("Success", 4), (AEAD_TAG, 2))
        self.assertEqual(rc.aead_cause(objective, rc.inputs(objective.put1())), "unexplained")

    def test_libssh_authenticating_on_a_tag_failed_request_needs_its_keys_wrong_too(self):
        """wolfSSH rejects the USERAUTH_REQUEST's tag at step 3 and libssh authenticates on it."""

        def key(request, wolfssh_values=(), libssh_values=()):
            steps = self.steps()
            steps[3] = sent(3, request, claims=[claim("password")])
            objective = self.objective(steps, ("Success", 4), (AEAD_TAG, 3), wolfssh_values=wolfssh_values,
                                       libssh_values=libssh_values)
            return rc.root_cause_key(objective)

        # its counter (1 is its index) is wrong in any run: libssh acted on a packet it cannot verify
        self.assertEqual(key(sealed(USERAUTH_REQUEST, counter="fn_u32_5")),
                         "named:known_libssh_cve_2026_59847_authenticates_on_tag_failed_packet")
        # its keys are wrong in wolfSSH's run only: libssh may have authenticated rightly, so the
        # disagreement is an audit pile, not the CVE
        wolfssh = [value("session_id@0", [9, 9, 9])]
        libssh = [value("session_id@0", [1, 2, 3]), value("exchange_hash_0@0", [1, 2, 3], "ExchangeHash")]
        self.assertEqual(key(sealed(USERAUTH_REQUEST), wolfssh, libssh), "auth_unexplained:server")

    def test_libssh_getting_past_a_packet_its_own_keys_cannot_verify_confirms_it(self):
        """No request after the packet: what confirms the AES-GCM key is that libssh got past a packet
        whose tag cannot verify under libssh's own keys either."""

        def key(service_request, libssh_values=(), wolfssh_values=()):
            steps = self.steps(service_request)[:3] + [received(3)]
            libssh, wolfssh = ("Success", 3), (AEAD_TAG, 2)
            objective = self.objective(steps, libssh, wolfssh, (6,), (6,), wolfssh_values, libssh_values)
            return rc.root_cause_key(objective)

        # a wrong counter is wrong in every run
        self.assertEqual(key(sealed(SERVICE_REQUEST, counter="fn_u32_5")), "aead:server:wrong_invocation_counter")
        # keys derived from values that are not the PUT's, in libssh's run too ([8, 8, 8] is not [1, 2, 3])
        wolfssh, libssh = [value("session_id@0", [9, 9, 9])], [value("session_id@0", [8, 8, 8])]
        self.assertEqual(key(None, libssh, wolfssh), "aead:server:wrong_exchange_hash")
        # ... but not in libssh's: the packet may verify there
        libssh = [value("session_id@0", [1, 2, 3]), value("exchange_hash_0@0", [1, 2, 3], "ExchangeHash")]
        self.assertEqual(key(None, libssh, wolfssh), "aead:server:wrong_exchange_hash:unconfirmed")
        # libssh waits for the tag bytes a plaintext packet lacks: getting past it is no acceptance
        plaintext = t("fn_packet", SERVICE_REQUEST)
        self.assertEqual(key(plaintext), "aead:server:plaintext_after_newkeys:unconfirmed")

    def test_status_claim_and_shape_keys(self):
        wolfssh = ("RSA buffer error (rc=-1001 gerr=-1018)", 2)
        objective = self.objective(self.steps(), ("Success", 4), wolfssh, libssh_sent=(6,))
        self.assertEqual(rc.root_cause_key(objective), "status:server:W:wolfssh_gerr1018")
        # a stale -180 next to a return code other than WS_FATAL_ERROR is not an AES-GCM failure
        libssh, wolfssh = ("SESSION_ERROR: Packet filter: x", 2), ("Invalid state (rc=-1030 gerr=-180)", 2)
        objective = self.objective(self.steps(), libssh, wolfssh, libssh_sent=(6,))
        self.assertEqual(rc.root_cause_key(objective), "status:server:=:libssh_packet_filter|wolfssh_gerr1030")
        steps = self.steps()
        types = {"agent": 0, "index": 1, "first_type": "()", "second_type": "Box<SshClaimInner>"}
        claims = {"Claims": {"DifferentTypes": types}}
        objective = Objective(replay(steps, error="SESSION_ERROR: Packet filter: x"), replay(steps), [claims])
        self.assertEqual(rc.root_cause_key(objective), "claim:server:L:libssh_packet_filter")
        objective = Objective(
            replay(steps, knowledges=[aligned((6, 0), (91, 0), (91, 1))]),
            replay(steps, knowledges=[aligned((6, 0), (91, 0), (92, 0))]),
        )
        self.assertEqual(rc.root_cause_key(objective), "shape:server:L91.1/W92.0")


class Rekeys(unittest.TestCase):
    """A server under attack, rekeyed: NEWKEYS at step 1, a packet of the first keys at step 2, the rekey's
    NEWKEYS (sealed under the first keys) at step 3, then a packet of the rekey's keys at step 4, whose
    AES-GCM tag wolfSSH rejects. Both PUTs claim the exchange hashes [1, 2, 3] (the session id) and
    [4, 5, 6] (the rekey's)."""

    HASHES = ((1, 2, 3), (4, 5, 6))

    def objective(self, wolfssh_rekey_hash, libssh_rekey_hash=(4, 5, 6), kex=HASHES):
        steps = [
            received(0),
            sent(1, NEWKEYS, claims=[claim(kex=kex[:1] if kex is not None else None)]),
            sent(2, sealed(SERVICE_REQUEST), precomputations=SCHEDULE),
            sent(3, sealed(t("fn_new_keys")), precomputations=SCHEDULE, claims=[claim(kex=kex)]),
            sent(4, sealed_after_rekey(GLOBAL_REQUEST), precomputations=REKEY_SCHEDULE),
            received(5),
        ]

        def values(rekey_hash):
            return [
                value("session_id@0", [1, 2, 3]),
                value("exchange_hash_0@0", [1, 2, 3], "ExchangeHash"),
                value("exchange_hash_1@0", list(rekey_hash), "ExchangeHash"),
            ]

        return Objective(
            replay(steps, knowledges=[aligned((6, 0), (21, 1)), *values(libssh_rekey_hash)]),
            replay(steps[:5], knowledges=[aligned((6, 0), (21, 1)), *values(wolfssh_rekey_hash)]),
            [status_difference("Success", 5, AEAD_TAG, 4)],
        )

    def cause(self, objective):
        return rc.aead_cause(objective, rc.inputs(objective.put1()))

    def test_the_claims_give_the_exchange_hash_of_each_key_exchange(self):
        status = replay([sent(1, NEWKEYS, claims=[claim(kex=[(1, 2, 3)])]),
                         received(2, claims=[claim(kex=self.HASHES)])])
        self.assertEqual(rc.put_exchange_hashes(status), [bytes([1, 2, 3]), bytes([4, 5, 6])])
        # a claim from before the claims carried key-exchange secrets, and one with none
        self.assertEqual(rc.put_exchange_hashes(replay([sent(1, NEWKEYS, claims=[claim()])])), [])
        self.assertEqual(rc.put_exchange_hashes(replay([sent(1, NEWKEYS, claims=[claim(kex=())])])), [])

    def test_the_exchange_hash_of_a_rekey_is_checked_against_the_one_the_put_claims(self):
        self.assertEqual(self.cause(self.objective((9, 9, 9))), "wrong_exchange_hash")
        self.assertEqual(self.cause(self.objective((4, 5, 6))), "unexplained")
        # claims without key-exchange secrets give no exchange hash for the rekey's keys: not decided
        self.assertEqual(self.cause(self.objective((9, 9, 9), kex=None)), "unexplained")

    def test_libssh_getting_past_a_packet_whose_rekey_hash_is_wrong_for_it_too_confirms_it(self):
        self.assertEqual(rc.root_cause_key(self.objective((9, 9, 9), (8, 8, 8))), "aead:server:wrong_exchange_hash")
        # the right exchange hash in libssh's run: the packet may verify there
        self.assertEqual(rc.root_cause_key(self.objective((9, 9, 9))), "aead:server:wrong_exchange_hash:unconfirmed")

    def test_a_stale_schedule_needs_libssh_in_the_key_epoch_of_the_packet(self):
        """Two rekeys: the packet of step 6 is in the third key epoch, so libssh must have sent the NEWKEYS of
        the second rekey (21.2); that of the first (21.1) is not enough."""
        rekey_newkeys = sealed(t("fn_new_keys"))
        steps = [received(0), sent(1, NEWKEYS, claims=[claim()]),
                 sent(2, sealed(SERVICE_REQUEST), precomputations=SCHEDULE), sent(3, rekey_newkeys),
                 sent(4, sealed(SERVICE_REQUEST)), sent(5, rekey_newkeys), sent(6, sealed(SERVICE_REQUEST))]

        def invalid(*libssh_sent):
            objective = Objective(replay(steps, knowledges=[aligned(*libssh_sent)]), replay(steps))
            inp = rc.inputs(objective.put1())
            return rc.invalid_for_libssh(objective, inp, "stale_pre_rekey_schedule", 6)

        self.assertFalse(invalid((21, 0), (21, 1)))
        self.assertTrue(invalid((21, 0), (21, 1), (21, 2)))


if __name__ == "__main__":
    unittest.main()
