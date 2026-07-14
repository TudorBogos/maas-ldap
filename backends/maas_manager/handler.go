package maas_manager

import (
	"encoding/json"
	"net/http"
	"net/url"

	"maas-ldap/config"
	"maas-ldap/ldap"
	"maas-ldap/proxy"
)

// NewHandler creates the maas-manager login endpoint handler from bootstrap config.
func NewHandler(appConfig config.AppConfig, target url.URL, allowedGroup string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handle(w, r, appConfig, target, allowedGroup)
	}
}

func handle(w http.ResponseWriter, r *http.Request, appConfig config.AppConfig, target url.URL, allowedGroup string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		WriteError(w, r.URL.Path, "Invalid HTTP method", "This page only accepts login submissions.", nil, http.StatusMethodNotAllowed)
		return
	}

	req, err := decodeLoginRequest(r)
	if err != nil {
		WriteError(w, r.URL.Path, "Invalid login request", "Please submit the login form again.", err, http.StatusBadRequest)
		return
	}

	entry, err := ldap.LdapSearch(req.Username, req.Password, appConfig.LDAP, []string{"memberOf"}, nil)
	if err != nil {
		WriteError(w, r.URL.Path, "LDAP search failed", "We could not verify your maas-manager access. Please try again or contact an administrator.", err, http.StatusUnauthorized)
		return
	}

	if err := ldap.CheckAllowedGroup(entry, allowedGroup); err != nil {
		WriteError(w, r.URL.Path, "User is not in the allowed LDAP group", "You are not allowed to access maas-manager.", err, http.StatusForbidden)
		return
	}

	proxyBody, err := json.Marshal(managerLoginRequest{Username: req.Username})
	if err != nil {
		WriteError(w, r.URL.Path, "Target request serialization failed", "We could not prepare your login request. Please try again later.", err, http.StatusInternalServerError)
		return
	}

	if err := proxy.ToTarget(w, r, target, proxyBody); err != nil {
		WriteError(w, r.URL.Path, "Target proxy failed", "maas-manager login is temporarily unavailable. Please try again later.", err, http.StatusBadGateway)
		return
	}
}
