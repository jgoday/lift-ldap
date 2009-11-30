package net.liftweb.ldap

import java.io.{InputStream, FileInputStream}
import java.util.{Hashtable, Properties}

import javax.naming.Context
import javax.naming.directory.{BasicAttributes, SearchControls}
import javax.naming.ldap.{LdapName, InitialLdapContext}

import scala.collection.jcl.{Hashtable => ScalaHashtable, MapWrapper}
import scala.util.logging.{Logged, ConsoleLogger}

/**
 * Extends SimpleLDAPVendor trait,
 * Allow us to search and bind an username from a ldap server
 * To set the ldap server parameters override the parameters var directly:
 *    SimpleLDAPVendor.parameters = () => Map("ldap.username" -> ...
 * or set the parameters from a properties file or a inputStream
 *    SimpleLDAPVendor.parameters = () => SimpleLDAPVendor.parametersFromFile("/opt/config/ldap.properties")
 *    SimpleLDAPVendor.parameters = () => SimpleLDAPVendor.parametersFromStream(
                this.getClass().getClassLoader().getResourceAsStream("ldap.properties"))
 *
 * The mandatory parameters are :
 *  ldap.url -> LDAP Server url : ldap://localhost
 *  ldap.base -> Base DN from the LDAP Server : dc=company, dc=com
 *  ldap.userName -> LDAP user dn to perform search operations
 *  ldap.password -> LDAP user password
 */
object SimpleLDAPVendor extends SimpleLDAPVendor with ConsoleLogger {
    def parametersFromFile(filename: String) : StringMap = {
        return parametersFromStream(new FileInputStream(filename))
    }

    def parametersFromStream(stream: InputStream) : StringMap = {
        val p = new Properties()
        p.load(stream)

        return convertToStringMap(p.asInstanceOf[Hashtable[String, String]])
    }

    private def convertToStringMap(javaMap: Hashtable[String, String]) = {
        Map.empty ++ new MapWrapper[String, String]() {
            def underlying = javaMap
        }
    }
}

trait SimpleLDAPVendor extends LDAPVendor

class LDAPVendor extends Logged {

    type StringMap = Map[String, String]

    val DEFAULT_URL = "localhost"
    val DEFAULT_BASE_DN = ""
    val DEFAULT_USER = ""
    val DEFAULT_PASSWORD = ""
    val DEFAULT_INITIAL_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory"

    var parameters: () => StringMap = () => null

    lazy val initialContext = getInitialContext(parameters())

    def search(filter: String) : List[String] = {
        log("--> LDAPSearch.search: Searching for '%s'".format(filter))

        var list = List[String]()

        val ctx = initialContext

        if (!ctx.isEmpty) {
            val result = ctx.get.search(parameters().getOrElse("ldap.base", DEFAULT_BASE_DN),
                                        filter,
                                        getSearchControls())

            while(result.hasMore()) {
                var r = result.next()
                list = list ::: List(r.getName)
            }
        }

        return list
    }

    def bindUser(dn: String, password: String) : Boolean = {
        log("--> LDAPSearch.bindUser: Try to bind user '%s'".format(dn))

        var result = false

        try {
            val username = dn + "," + parameters().getOrElse("ldap.base", DEFAULT_BASE_DN)
            var ctx = getInitialContext(parameters() ++ Map("ldap.userName" -> username,
                                                            "ldap.password" -> password))
            result = !ctx.isEmpty
            ctx.get.close
        }
        catch {
            case e: Exception => println(e)
        }

        log("--> LDAPSearch.bindUser: Bind successfull ? %s".format(result))

        return result
    }

    // TODO : Allow search controls && attributes without override method ?
    def getSearchControls() : SearchControls = {
        val searchAttributes = new Array[String](1)
        searchAttributes(0) = "cn"

        val constraints = new SearchControls()
        constraints.setSearchScope(SearchControls.SUBTREE_SCOPE)
        constraints.setReturningAttributes(searchAttributes)
        return constraints
    }

    private def getInitialContext(props: StringMap) : Option[InitialLdapContext] = {
        log("--> LDAPSearch.getInitialContext: Get initial context from '%s'".format(props.get("ldap.url")))

        var env = new Hashtable[String, String]()
        env.put(Context.PROVIDER_URL, props.getOrElse("ldap.url", DEFAULT_URL))
        env.put(Context.SECURITY_AUTHENTICATION, "simple")
        env.put(Context.SECURITY_PRINCIPAL, props.getOrElse("ldap.userName", DEFAULT_USER))
        env.put(Context.SECURITY_CREDENTIALS, props.getOrElse("ldap.password", DEFAULT_PASSWORD))
        env.put(Context.INITIAL_CONTEXT_FACTORY, parameters().getOrElse("ldap.initial_context_factory",
                                                                        DEFAULT_INITIAL_CONTEXT_FACTORY))
        return Some(new InitialLdapContext(env, null))
    }
}
