// RUN: make test
// RUN-SOME: java -cp build/test:build/sekreto-cli.jar:$OMNI/kotlin/build/omnitest.jar \
//               SekretoTest envkey
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.
//
// No third-party test framework: a failing omni check throws OmniError, so
// any host framework (JUnit, kotlin.test) reports it as a failure. This
// harness keeps `make test` dependency-free.
//
// Two value models meet here. omni has a sealed `Json` with an `Absent`
// variant; the library takes plain Kotlin values and typed specs. The
// bridge below converts between them explicitly, so nothing about
// absent/null/value is guessed.

@file:JvmName("SekretoTest")

import com.voxgig.sekreto.AuthSpec
import com.voxgig.sekreto.ProviderSpec
import com.voxgig.sekreto.Sekreto
import com.voxgig.sekreto.Signing
import com.voxgig.sekreto.awsparam
import com.voxgig.sekreto.envkey
import com.voxgig.sekreto.flatname
import com.voxgig.sekreto.parsedotenv
import com.voxgig.sekreto.redact
import com.voxgig.sekreto.sekreto
import com.voxgig.sekreto.sigv4
import com.voxgig.sekreto.validname
import com.voxgig.sekreto.vaultref
import java.io.File
import kotlin.system.exitProcess
import voxgig.omni.Flags
import voxgig.omni.Json
import voxgig.omni.OmniError
import voxgig.omni.RunPack
import voxgig.omni.Subject
import voxgig.omni.errmessage
import voxgig.omni.makeRunner
import voxgig.omni.stringify

private var only: String? = null
private var passcount = 0
private var failcount = 0

/** Find the shared spec directory by walking up from the working directory. */
fun specfile(name: String): String {
    var dir: File? = File(System.getProperty("user.dir"))

    for (step in 0 until 8) {
        if (null == dir) {
            break
        }
        val cand = File(File(dir, "spec"), name)
        if (cand.exists()) {
            return cand.absolutePath
        }
        dir = dir.parentFile
    }

    throw OmniError("sekreto: spec not found: $name")
}

// ------------------------------------------------------------ the bridge

/** omni's model -> a plain Kotlin value. Absent and null both read as null. */
fun plain(value: Json): Any? = when (value) {
    is Json.Absent -> null
    is Json.Null -> null
    is Json.Bool -> value.value
    is Json.Num -> value.value
    is Json.Str -> value.value
    is Json.JList -> value.value.map { plain(it) }
    is Json.JMap -> value.value.mapValues { plain(it.value) }
}

/** A plain Kotlin value -> omni's model. */
fun toomni(value: Any?): Json = when (value) {
    null -> Json.Null
    is Boolean -> Json.Bool(value)
    is Number -> Json.num(value)
    is String -> Json.str(value)
    is List<*> -> Json.JList(value.mapTo(mutableListOf()) { toomni(it) })
    is Map<*, *> -> Json.JMap(
        LinkedHashMap<String, Json>().also { out ->
            value.forEach { (key, entry) -> out["$key"] = toomni(entry) }
        },
    )
    else -> Json.str(value.toString())
}

/** A list of strings, as omni compares them. */
fun textlist(values: List<String>): Json =
    Json.JList(values.mapTo(mutableListOf()) { Json.str(it) })

/** One provider spec, out of the spec's declarative chain description. */
fun specof(entry: Json): ProviderSpec {
    val values = entry.get("values").asmap?.let { given ->
        LinkedHashMap<String, String>().also { out ->
            given.forEach { (key, value) -> out[key] = stringify(value) }
        }
    }

    val auth = entry.get("auth").let { given ->
        if (!given.ismap) {
            null
        } else {
            AuthSpec(
                method = given.get("method").asstr ?: "",
                mount = given.get("mount").asstr,
                role = given.get("role").asstr,
                jwt = given.get("jwt").asstr,
                jwtfile = given.get("jwtfile").asstr,
                roleid = given.get("roleid").asstr,
                secretid = given.get("secretid").asstr,
            )
        }
    }

    return ProviderSpec(
        kind = entry.get("kind").asstr ?: "",
        name = entry.get("name").asstr,
        prefix = entry.get("prefix").asstr,
        file = entry.get("file").asstr,
        values = values,
        dir = entry.get("dir").asstr,
        addr = entry.get("addr").asstr,
        token = entry.get("token").asstr,
        mount = entry.get("mount").asstr,
        kv = entry.get("kv").asnum?.toInt(),
        vaultnamespace = entry.get("vaultnamespace").asstr,
        auth = auth,
        command = entry.get("command").asstr,
        profile = entry.get("profile").asstr,
        backend = entry.get("backend").asstr,
        reason = entry.get("reason").asstr,
        namespace = entry.get("namespace").asstr,
        home = entry.get("home").asstr,
        region = entry.get("region").asstr,
        keyid = entry.get("keyid").asstr,
        secret = entry.get("secret").asstr,
        session = entry.get("session").asstr,
        project = entry.get("project").asstr,
        vault = entry.get("vault").asstr,
        tenant = entry.get("tenant").asstr,
        clientid = entry.get("clientid").asstr,
        clientsecret = entry.get("clientsecret").asstr,
        loginaddr = entry.get("loginaddr").asstr,
        imdsaddr = entry.get("imdsaddr").asstr,
        metadataaddr = entry.get("metadataaddr").asstr,
        apiversion = entry.get("apiversion").asstr,
        config = entry.get("config").asstr,
        environment = entry.get("environment").asstr,
        path = entry.get("path").asstr,
    )
}

/** Build a Sekreto from the spec's declarative chain description. */
fun chainof(entry: Json): Sekreto {
    val chain = entry.get("chain").aslist ?: mutableListOf()
    return sekreto(chain.map { specof(it) }, cache = false)
}

/** The name a group's entry asks about. */
fun namearg(entry: Json): String = entry.get("name").asstr ?: ""

// ----------------------------------------------------------- the subjects

// `validname` answers whatever the language calls true; the spec says JSON
// true, so the adaptation happens here rather than in the library.
val VALIDNAME: Subject = { args -> Json.Bool(validname(plain(args[0]))) }

val ENVKEY: Subject = { args ->
    Json.str(envkey(plain(args[0].get("name")), args[0].get("prefix").asstr))
}

val VAULTREF: Subject = { args ->
    val ref = vaultref(plain(args[0]))
    Json.map("path" to Json.str(ref.path), "field" to Json.str(ref.field))
}

val FLATNAME: Subject = { args ->
    Json.str(flatname(plain(args[0].get("name")), args[0].get("sep").asstr ?: ""))
}

val AWSPARAM: Subject = { args ->
    Json.str(awsparam(plain(args[0].get("name")), args[0].get("prefix").asstr))
}

val PARSEDOTENV: Subject = { args -> toomni(parsedotenv(plain(args[0]))) }

val RESOLVE: Subject = { args -> Json.str(chainof(args[0]).get(namearg(args[0]))) }

val TRYSECRET: Subject = { args -> toomni(chainof(args[0]).tryget(namearg(args[0]))) }

val SOURCES: Subject = { args -> textlist(chainof(args[0]).sources()) }

val STORES: Subject = { args -> textlist(chainof(args[0]).stores()) }

val GETFROM: Subject = { args ->
    Json.str(chainof(args[0]).getfrom(args[0].get("store").asstr ?: "", namearg(args[0])))
}

val TRYFROM: Subject = { args ->
    toomni(chainof(args[0]).tryfrom(args[0].get("store").asstr ?: "", namearg(args[0])))
}

// Answers the ordered output map itself, which omni compares as a JSON
// object against the spec's known-answer signatures.
val SIGV4: Subject = { args ->
    val entry = args[0]

    val signed = sigv4(
        Signing(
            method = entry.get("method").asstr ?: "",
            url = entry.get("url").asstr ?: "",
            service = entry.get("service").asstr ?: "",
            region = entry.get("region").asstr ?: "",
            keyid = entry.get("keyid").asstr ?: "",
            secret = entry.get("secret").asstr ?: "",
            datetime = entry.get("datetime").asstr ?: "",
            headers = entry.get("headers").asmap?.mapValues { stringify(it.value) } ?: emptyMap(),
            body = entry.get("body").asstr ?: "",
            session = entry.get("session").asstr,
        ),
    )

    toomni(signed)
}

val REDACT: Subject = { args ->
    Json.str(
        redact(
            plain(args[0].get("text")),
            args[0].get("values").aslist?.map { plain(it) },
        ),
    )
}

// ------------------------------------------------------------- the runner

fun testcase(name: String, body: () -> Unit) {
    val filter = only
    if (null != filter && name != filter) {
        return
    }

    try {
        body()
        passcount++
        println("ok   - $name")
    } catch (err: Throwable) {
        failcount++
        println("FAIL - $name")
        println(errmessage(err))
    }
}

fun main(args: Array<String>) {
    if (args.isNotEmpty()) {
        only = args[0]
    }

    val R: RunPack = makeRunner(specfile("sekreto.json")).runner("sekreto")

    testcase("validname") { R.runsetflags(R.set("validname"), Flags.nonull(), VALIDNAME) }
    testcase("envkey") { R.runset(R.set("envkey"), ENVKEY) }
    testcase("vaultref") { R.runset(R.set("vaultref"), VAULTREF) }
    testcase("flatname") { R.runset(R.set("flatname"), FLATNAME) }
    testcase("awsparam") { R.runset(R.set("awsparam"), AWSPARAM) }
    testcase("parsedotenv") { R.runset(R.set("parsedotenv"), PARSEDOTENV) }
    testcase("resolve") { R.runset(R.set("resolve"), RESOLVE) }
    testcase("trysecret") { R.runset(R.set("trysecret"), TRYSECRET) }
    testcase("sources") { R.runset(R.set("sources"), SOURCES) }
    testcase("stores") { R.runset(R.set("stores"), STORES) }
    testcase("getfrom") { R.runset(R.set("getfrom"), GETFROM) }
    testcase("tryfrom") { R.runset(R.set("tryfrom"), TRYFROM) }
    testcase("sigv4") { R.runset(R.set("sigv4"), SIGV4) }
    testcase("redact") { R.runset(R.set("redact"), REDACT) }

    println("\n$passcount passed, $failcount failed")

    exitProcess(if (0 == failcount) 0 else 1)
}
