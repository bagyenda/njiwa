/*
 * Njiwa Open Source Embedded M2M UICC Remote Subscription Manager
 * 
 * 
 * Copyright (C) 2019 - , Digital Solutions Ltd. - http://www.dsmagic.com
 *
 * Njiwa Dev <dev@njiwa.io>
 * 
 * This program is free software, distributed under the terms of
 * the GNU General Public License.
 */

package io.njiwa.common.rest;

import io.njiwa.common.Utils;
import io.njiwa.common.model.Group;
import io.njiwa.common.rest.auth.UserData;
import io.njiwa.common.rest.types.RestResponse;
import io.njiwa.common.rest.types.Roles;
import org.picketlink.Identity;
import org.picketlink.credential.DefaultLoginCredentials;
import org.picketlink.idm.model.Account;

import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.Response;
import java.util.Set;

/**
 * Created by bagyenda on 15/06/2017.
 */

@Path("/auth")
public class Auth {

    @PersistenceContext
    private EntityManager em;
    @Inject
    private Identity identity;

    @Inject
    private DefaultLoginCredentials credentials;

   // @Context
   // private HttpServletRequest httpRequest;

    @Inject
    private UserData userData;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/logout")
    public Response logout() {
      if (identity.isLoggedIn())
          identity.logout();
      return Response.ok(io.njiwa.common.Utils.buildJSON(new RestResponse(RestResponse.Status.Success,""))).build();
    }

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("/login")
    public Response login(DefaultLoginCredentials credential, @Context HttpServletRequest request) throws Exception {
        AuthenticationResponse response = new AuthenticationResponse();
        String sessId = request.getSession().getId();

        if (!identity.isLoggedIn()) {
            String u = credential.getUserId();
            this.credentials.setUserId(u);
            this.credentials.setPassword(credential.getPassword());
            this.identity.login();

            if (this.identity.isLoggedIn()) {
                Account account = identity.getAccount();
                response.status = RestResponse.Status.Success;
                response.response = account;

                if (userData != null) {
                    // Pick up other key data
                   response.ownerEntity = userData.getEntityId();
                   response.ownerEntityType = userData.getEntityType();
                }

                response.roles = Group.userRoles(em, u);
            } else {
                response.status = RestResponse.Status.Failed;
                response.errors.add("Login failed!");
            }
        } else {
            response.status = RestResponse.Status.Success;
            response.response = this.identity.getAccount();
            response.errors.add("Already logged on!");
        }
        return Response.ok(io.njiwa.common.Utils.buildJSON(response))
                .cookie(new NewCookie("JSESSIONID", sessId))
                .build();
    }


    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/check")
    public Response checkLogon() {
        RestResponse response = new RestResponse();
        if (identity.isLoggedIn()) {
            response.status = RestResponse.Status.Success;
            response.response = "true";
        } else {
            response.status = RestResponse.Status.Failed;
            response.response = "false";
        }

        return Response.ok(Utils.buildJSON(response))
                .build();
    }


    public class AuthenticationResponse extends RestResponse {
        public Account response;
        public long ownerEntity;
        public String ownerEntityType;
        public Set<String> roles;
        public final String[] allRoles = Roles.ALL_ROLES;
    }
}
