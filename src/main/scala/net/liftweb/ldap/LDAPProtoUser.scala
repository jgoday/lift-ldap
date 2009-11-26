package net.liftweb.ldap

import scala.xml.{Elem, NodeSeq}
import net.liftweb.http.{LiftResponse, S}
import net.liftweb.http.js.{JsCmds}
import net.liftweb.mapper.{BaseOwnedMappedField,
                           MappedString,
                           MetaMegaProtoUser,
                           MegaProtoUser}
import net.liftweb.sitemap.{Menu}
import net.liftweb.util.{Helpers}
import net.liftweb.common.{Box, Empty, Full}

import Helpers._

trait MetaLDAPProtoUser[ModelType <: LDAPProtoUser[ModelType]] extends MetaMegaProtoUser[ModelType] {
    self: ModelType =>

    override def signupFields: List[BaseOwnedMappedField[ModelType]] = uid ::
        cn :: dn :: Nil

    override def fieldOrder: List[BaseOwnedMappedField[ModelType]] = uid ::
        cn :: dn :: Nil

    /**
     * The menu item for creating the user/sign up (make this "Empty" to disable)
     */
    override def createUserMenuLoc: Box[Menu] = Empty

    /**
     * The menu item for lost password (make this "Empty" to disable)
     */
    override def lostPasswordMenuLoc: Box[Menu] = Empty

    /**
     * The menu item for resetting the password (make this "Empty" to disable)
     */
    override def resetPasswordMenuLoc: Box[Menu] = Empty

    /**
     * The menu item for changing password (make this "Empty" to disable)
     */
    override def changePasswordMenuLoc: Box[Menu] = Empty

    /**
     * The menu item for validating a user (make this "Empty" to disable)
     */
    override def validateUserMenuLoc: Box[Menu] = Empty

    override def editUserMenuLoc: Box[Menu] = Empty

    override def loginXhtml : Elem = {
        <form method="post" action={S.uri}>
            <table>
                <tr>
                    <td colspan="2">{S.??("log.in")}</td>
                </tr>
                <tr>
                    <td>Username</td><td><user:name /></td>
                </tr>
                <tr>
                    <td>Password</td><td><user:password /></td>
                </tr>
                <tr>
                    <td>&nbsp;</td><td><user:submit /></td>
                </tr>
            </table>
        </form>
    }

    def ldapVendor: SimpleLDAPVendor = SimpleLDAPVendor

    def login(setRolesFunction: (String, LDAPVendor) => AnyRef) : NodeSeq = {
        if (S.post_?) {
            val users = ldapVendor.search("(uid=" + S.param("username").openOr("") + ")")

            if (users.size >= 1) {
                val userDn = users(0)
                if (ldapVendor.bindUser(userDn,
                                        S.param("password").openOr(""))) {
                    logUserIn(this)
                    setRolesFunction(userDn, ldapVendor)
                }
                else {
                    S.error("Unable to login with : " + S.param("username").openOr(""))
                }
            }
            else {
                S.error("Unable to login with : " + S.param("username").openOr(""))
            }
        }

    /**
    S.param("username").
        foreach(username =>
            openIDVendor.loginAndRedirect(username, performLogUserIn)
        )**/

/*
        def performLogUserIn(openid: Box[Identifier], fo: Box[VerificationResult], exp: Box[Exception]): LiftResponse = {
            (openid, exp) match {
                case (Full(id), _) =>
                    val user = self.findOrCreate(id.getIdentifier)
                    logUserIn(user)
                    S.notice(S.??("Welcome ")+user.niceName)

                case (_, Full(exp)) =>
                    S.error("Got an exception: "+exp.getMessage)

                case _ =>
                    S.error("Unable to log you in: "+fo)
            }

            RedirectResponse("/")
        }
*/
        Helpers.bind("user", loginXhtml,
                    "name" -> (JsCmds.FocusOnLoad(<input type="text" name="username"/>)),
                    "password" -> (JsCmds.FocusOnLoad(<input type="password" name="password"/>)),
                    "submit" -> (<input type="submit" value={S.??("log.in")}/>))
    }
}

trait LDAPProtoUser[T <: LDAPProtoUser[T]] extends MegaProtoUser[T] {
    self: T =>

    override def getSingleton: MetaLDAPProtoUser[T]

    object uid extends MappedString(this, 64) {
        override def dbIndexed_? = true
    }

    object dn extends MappedString(this, 64) {
        override def dbIndexed_? = true
    }

    object cn extends MappedString(this, 64) {
        override def dbIndexed_? = true
    }
}
