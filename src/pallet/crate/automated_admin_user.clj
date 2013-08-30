(ns pallet.crate.automated-admin-user
  (:require
   [pallet.actions :refer [directory package-manager plan-when-not user]]
   [pallet.api :refer [plan-fn] :as api]
   [pallet.crate :refer [admin-user defplan]]
   [pallet.crate.ssh-key :as ssh-key]
   [pallet.crate.sudoers :as sudoers]
   [pallet.script.lib :refer [user-home]]
   [pallet.stevedore :refer [fragment]]
   [pallet.utils :refer [apply-map]]))

(defplan authorize-user-key
  "Authorise a single key, specified as a path or as a byte array."
  [username path-or-bytes]
  (if (string? path-or-bytes)
    (ssh-key/authorize-key username (slurp path-or-bytes))
    (ssh-key/authorize-key username (String. ^bytes path-or-bytes))))

(defplan create-admin
  "Builds a user for use in remote-admin automation. The user is given
  permission to sudo without password, so that passwords don't have to appear
  in scripts, etc."
  [& {:keys [username public-key-paths sudo create-user create-home]
      :or {sudo true
           create-home ::unspecified
           create-user ::unspecified}}]
  (let [admin (admin-user)
        username (or username (:username admin))
        public-key-paths (or public-key-paths [(:public-key-path admin)])]
    (when sudo
      (sudoers/install))
    (when (and (not= ::unspecified create-user) create-user)
      (user username :create-home true :shell :bash))
    (when (= ::unspecified create-user)
      ;; If the user exists and the home directory does not
      ;; then create it? This is to allow for pam_mkhomedir,
      ;; and is a hack, as it doesn't copy /etc/skel
      (directory (fragment (user-home ~username)) :owner username)
      ;; if create-user not forced, only run if no existing user,
      ;; so we can run in the presence of pam_ldap users.
      (plan-when-not (fragment ("getent" passed ~username))
        (user username :create-home true :shell :bash)))
    (when (and (not create-user) create-home)
      (directory (fragment (user-home ~username)) :owner username))
    (doseq [kp public-key-paths]
      (authorize-user-key username kp))
    (when sudo
      (sudoers/sudoers
       {}
       {:default {:env_keep "SSH_AUTH_SOCK"}}
       {username {:ALL {:run-as-user :ALL :tags :NOPASSWD}}}))))

(defn server-spec
  [{:keys [username public-key-paths sudo create-user create-home]
    :as options}]
  (api/server-spec
   :phases {:bootstrap (plan-fn
                        (package-manager :update)
                        (apply-map create-admin options))}))

(defplan automated-admin-user
  "Builds a user for use in remote-admin automation. The user is given
  permission to sudo without password, so that passwords don't have to appear
  in scripts, etc."
  ([]
     (let [user (admin-user)]
       (clojure.tools.logging/debugf "a-a-u for %s" user)
       (automated-admin-user
        (:username user)
        (:public-key-path user))))
  ([username]
     (let [user (admin-user)]
       (automated-admin-user username (:public-key-path user))))
  ([username & public-key-paths]
     (sudoers/install)
     (user username :create-home true :shell :bash)
     (doseq [kp public-key-paths]
       (authorize-user-key username kp))
     (sudoers/sudoers
      {}
      {:default {:env_keep "SSH_AUTH_SOCK"}}
      {username {:ALL {:run-as-user :ALL :tags :NOPASSWD}}})))

(def with-automated-admin-user
  (api/server-spec
   :phases {:bootstrap (plan-fn
                          (package-manager :update)
                          (automated-admin-user))}))
