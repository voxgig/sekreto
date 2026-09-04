// RUN: make test
// RUN-SOME: java -cp build/test:build/sekreto-cli.jar:$OMNI/scala/build \
//               SekretoTest envkey
//
// The sekreto conformance suite. Every port runs these same groups, from
// the same spec/sekreto.json, through its own voxgig/omni runner.
//
// No third-party test framework: a failing omni check throws OmniError, so
// any host framework (ScalaTest, munit) reports it as a failure. This
// harness keeps `make test` dependency-free.
//
// Two value models meet here. omni has an enum `Json` with an `Absent`
// case; the library takes plain Scala values and typed specs. The bridge
// below converts between them explicitly, so nothing about absent, null and
// value is guessed.

import java.io.File
import scala.collection.immutable.ListMap
import scala.util.control.NonFatal

import voxgig.omni.{Flags, Json, OmniError, Provider, RunPack, Runner, Subject, Util}

import com.voxgig.sekreto.{
  AuthSpec,
  ProviderSpec,
  Sekreto,
  Signing,
  awsparam,
  envkey,
  flatname,
  parsedotenv,
  redact,
  sekreto as makesekreto,
  sigv4,
  validname,
  vaultref,
}

object SekretoTest:

  private var only: Option[String] = None
  private var passcount = 0
  private var failcount = 0

  /** Find the shared spec directory by walking up from the working dir. */
  def specfile(name: String): String =
    var dir = File(System.getProperty("user.dir"))
    var found: Option[String] = None
    var step = 0

    while found.isEmpty && step < 8 && null != dir do
      val cand = File(File(dir, "spec"), name)
      if cand.exists then found = Some(cand.getAbsolutePath)
      else dir = dir.getParentFile
      step += 1

    found.getOrElse(throw OmniError(s"sekreto: spec not found: $name"))

  // ---------------------------------------------------------- the bridge

  /** omni's model -> a plain Scala value. Absent and null both read as
    * null, which is what the library's `Any` entry points expect.
    */
  def plain(value: Json): Any = value match
    case Json.Absent         => null
    case Json.Null           => null
    case Json.Bool(entry)    => entry
    case Json.Num(entry)     => entry
    case Json.Str(entry)     => entry
    case Json.JList(entries) => entries.map(plain)
    case Json.JMap(entries)  => entries.map((key, entry) => (key, plain(entry)))

  /** A plain Scala value -> omni's model. */
  def toomni(value: Any): Json = value match
    case null            => Json.Null
    case entry: Boolean  => Json.Bool(entry)
    case entry: Double   => Json.Num(entry)
    case entry: Int      => Json.Num(entry.toDouble)
    case entry: String   => Json.Str(entry)
    case entry: Option[?] => entry.map(toomni).getOrElse(Json.Null)
    case entry: List[?]  => Json.JList(entry.map(toomni))
    case entry: Map[?, ?] =>
      Json.JMap(ListMap.from(entry.map((key, item) => (s"$key", toomni(item)))))
    case other => Json.Str(other.toString)

  /** A list of strings, as omni compares them. */
  def textlist(values: List[String]): Json = Json.JList(values.map(Json.Str.apply))

  /** One provider spec, out of the spec's declarative chain description. */
  def specof(entry: Json): ProviderSpec =
    val values = entry
      .get("values")
      .asmap
      .map(source => ListMap.from(source.map((key, value) => (key, Util.stringify(value)))))

    val auth =
      if !entry.get("auth").ismap then None
      else
        val useauth = entry.get("auth")
        Some(
          AuthSpec(
            method = useauth.get("method").asstr.getOrElse(""),
            mount = useauth.get("mount").asstr,
            role = useauth.get("role").asstr,
            jwt = useauth.get("jwt").asstr,
            jwtfile = useauth.get("jwtfile").asstr,
            roleid = useauth.get("roleid").asstr,
            secretid = useauth.get("secretid").asstr,
          ),
        )

    ProviderSpec(
      kind = entry.get("kind").asstr.getOrElse(""),
      name = entry.get("name").asstr,
      prefix = entry.get("prefix").asstr,
      file = entry.get("file").asstr,
      values = values,
      dir = entry.get("dir").asstr,
      addr = entry.get("addr").asstr,
      token = entry.get("token").asstr,
      mount = entry.get("mount").asstr,
      kv = entry.get("kv").asnum.map(_.toInt),
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

  /** Build a Sekreto from the spec's declarative chain description. */
  def chainof(entry: Json): Sekreto =
    makesekreto(entry.get("chain").aslist.getOrElse(List.empty).map(specof), cache = false)

  /** The name a group's entry asks about. */
  def namearg(entry: Json): String = entry.get("name").asstr.getOrElse("")

  // --------------------------------------------------------- the subjects

  // `validname` answers whatever the language calls true; the spec says JSON
  // true, so the adaptation happens here rather than in the library.
  val VALIDNAME: Subject = args => Json.Bool(validname(plain(args.head)))

  val ENVKEY: Subject = args =>
    Json.Str(envkey(plain(args.head.get("name")), args.head.get("prefix").asstr))

  val VAULTREF: Subject = args =>
    val ref = vaultref(plain(args.head))
    Json.map("path" -> Json.Str(ref.path), "field" -> Json.Str(ref.field))

  val FLATNAME: Subject = args =>
    Json.Str(flatname(plain(args.head.get("name")), args.head.get("sep").asstr.getOrElse("")))

  val AWSPARAM: Subject = args =>
    Json.Str(awsparam(plain(args.head.get("name")), args.head.get("prefix").asstr))

  val PARSEDOTENV: Subject = args => toomni(parsedotenv(plain(args.head)))

  val RESOLVE: Subject = args => Json.Str(chainof(args.head).get(namearg(args.head)))

  val TRYSECRET: Subject = args => toomni(chainof(args.head).tryget(namearg(args.head)))

  val SOURCES: Subject = args => textlist(chainof(args.head).sources())

  val STORES: Subject = args => textlist(chainof(args.head).stores())

  val GETFROM: Subject = args =>
    Json.Str(
      chainof(args.head).getfrom(args.head.get("store").asstr.getOrElse(""), namearg(args.head)),
    )

  val TRYFROM: Subject = args =>
    toomni(
      chainof(args.head).tryfrom(args.head.get("store").asstr.getOrElse(""), namearg(args.head)),
    )

  // Answers the ordered output map itself, which omni compares as a JSON
  // object against the spec's known-answer signatures.
  val SIGV4: Subject = args =>
    val entry = args.head

    val signed = sigv4(
      Signing(
        method = entry.get("method").asstr.getOrElse(""),
        url = entry.get("url").asstr.getOrElse(""),
        service = entry.get("service").asstr.getOrElse(""),
        region = entry.get("region").asstr.getOrElse(""),
        keyid = entry.get("keyid").asstr.getOrElse(""),
        secret = entry.get("secret").asstr.getOrElse(""),
        datetime = entry.get("datetime").asstr.getOrElse(""),
        headers = entry
          .get("headers")
          .asmap
          .map(source => ListMap.from(source.map((key, value) => (key, Util.stringify(value)))))
          .getOrElse(ListMap.empty),
        body = entry.get("body").asstr.getOrElse(""),
        session = entry.get("session").asstr,
      ),
    )

    toomni(signed)

  val REDACT: Subject = args =>
    Json.Str(
      redact(
        plain(args.head.get("text")),
        args.head.get("values").aslist.map(_.map(plain)),
      ),
    )

  // ---------------------------------------------------------- the runner

  def testcase(name: String)(body: => Unit): Unit =
    if only.exists(_ != name) then return

    try
      body
      passcount += 1
      println(s"ok   - $name")
    catch
      case NonFatal(err) =>
        failcount += 1
        println(s"FAIL - $name")
        println(Runner.errmessage(err))

  def main(args: Array[String]): Unit =
    if args.nonEmpty then only = Some(args(0))

    val R: RunPack = Runner.makeRunner(specfile("sekreto.json"), Provider()).runner("sekreto")

    testcase("validname")(R.runsetflags(R.set("validname"), Flags.nonull(), Some(VALIDNAME)))
    testcase("envkey")(R.runset(R.set("envkey"), Some(ENVKEY)))
    testcase("vaultref")(R.runset(R.set("vaultref"), Some(VAULTREF)))
    testcase("flatname")(R.runset(R.set("flatname"), Some(FLATNAME)))
    testcase("awsparam")(R.runset(R.set("awsparam"), Some(AWSPARAM)))
    testcase("parsedotenv")(R.runset(R.set("parsedotenv"), Some(PARSEDOTENV)))
    testcase("resolve")(R.runset(R.set("resolve"), Some(RESOLVE)))
    testcase("trysecret")(R.runset(R.set("trysecret"), Some(TRYSECRET)))
    testcase("sources")(R.runset(R.set("sources"), Some(SOURCES)))
    testcase("stores")(R.runset(R.set("stores"), Some(STORES)))
    testcase("getfrom")(R.runset(R.set("getfrom"), Some(GETFROM)))
    testcase("tryfrom")(R.runset(R.set("tryfrom"), Some(TRYFROM)))
    testcase("sigv4")(R.runset(R.set("sigv4"), Some(SIGV4)))
    testcase("redact")(R.runset(R.set("redact"), Some(REDACT)))

    println(s"\n$passcount passed, $failcount failed")

    System.exit(if 0 == failcount then 0 else 1)
