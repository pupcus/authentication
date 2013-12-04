;; Copyright (c) pupcus.org. All rights reserved.
;; Copyright (c) Brenton Ashworth. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file COPYING at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns org.pupcus.authentication
  (:use [clojure.set :only [intersection]]
        [ring.util.response :only [redirect]]
        [slingshot.slingshot :only [throw+ try+]]
        [org.pupcus.stateful-sessions :only [session-get session-put! session-delete-key!]]))



;;
;; Working with context paths
;;


(def ^:dynamic app-context (atom ""))

(defn set-app-context!
  "Set the context path for this appliation. The context path will be used by
   cpath and clink-to so that you don't have to repeat it throughout the
   application."
  [context]
  (swap! app-context (constantly context)))

(defn cpath
  "Prefix a path starting with '/' with the context path."
  [path]
  (if (.startsWith path "/")
    (str @app-context path)
    path))

(defn remove-cpath
  "Strip the context path from a path."
  [path]
  (let [c @app-context]
    (if (and (not (empty? c))
             (.startsWith path c))
      (apply str (drop (count c) path))
      path)))

;;
;; Redirects
;;

(defn redirect-301 [url]
  {:status 301
   :headers {"Location" (cpath url)}})

(defn redirect? [m]
  (or (= (:status m) 302)
      (= (:status m) 301)))

(defn append-to-redirect-loc
  "Append the uri-prefix to the value of Location in the headers of the
   redirect map."
  [m uri-prefix]
  (if (or (nil? uri-prefix) (empty? uri-prefix))
    m
    (let [loc (remove-cpath ((:headers m) "Location"))]
      (if (re-matches #".*://.*" loc)
        m
        (merge m {:headers {"Location" (cpath (str uri-prefix loc))}})))))



(def ^:dynamic *hash-delay* 1000)

(def ^:dynamic *current-user* nil)


(defn- redirect-to-permission-denied [uri-prefix]
  (redirect (str uri-prefix "/permission-denied")))

(defn- redirect-to-authentication-error [uri-prefix]
  (redirect (str uri-prefix "/authentication-error")))

(defn- params-str [request]
  (let [p (:query-string request)]
    (if (not (empty? p)) (str "?" p) "")))

(defn to-https [request ssl-port]
  (let [host (:server-name request)]
    (str "https://" host ":" ssl-port (:uri request)
         (params-str request))))

(defn to-http [request port]
  (let [host (:server-name request)
        port (if (= port 80) "" (str ":" port))]
    (str "http://" host port (:uri request)
         (params-str request))))

(defn- role? [x]
  (not (or (= x :ssl) (= x :nossl) (= x :any-channel))))

(defn role-set
  "Return a set of roles or nil. The input could be a single role, a set of
   roles, :ssl or :nossl. The last two are not roles."
  [role]
  (cond (not (role? role)) nil
        (keyword? role) #{role}
        (set? role) role
        :else nil))

(defn find-matching-config
  "Find the configuration that matches the current uri."
  [coll request]
  (let [uri (:uri request)]
    (last
     (first
      (filter #(let [pred (first %)]
                 (if (fn? pred)
                   (pred request)
                   (re-matches pred (remove-cpath uri))))
              coll)))))

(defn required-roles
  "Get the set of roles that a user is required to have for the requested
   resource."
  [config request]
  (if (or (nil? config) (empty? config))
    #{:any}
    (let [role-part (find-matching-config (filter #(role? (last %))
                                                  (partition 2 config))
                                          request)]
      (cond (keyword? role-part) (role-set role-part)
            (vector? role-part) (role-set (first role-part))
            (set? role-part) role-part))))

(defn intersect-exists? [s1 s2]
  (not (empty? (intersection s1 s2))))

(defn allow-access?
  "Does user-roles plus :any contain any of the roles in required-roles?"
  [required-roles user-roles]
  (if required-roles
    (intersect-exists? (set (conj user-roles :any)) required-roles)
    false))

(defn auth-required?
  "Are there required roles other than :any."
  [required-roles]
  (not (and (= (count required-roles) 1)
            (= (first required-roles) :any))))

(defn filter-channel-config
  "Extract the channel configuration from the security configuration."
  [config]
  (map #(vector (first %) (if (vector? (last %))
                            (last (last %))
                            (last %)))
       (filter #(cond (and (keyword? (last %))
                           (not (role? (last %))))
                      true
                      (and (vector? (last %))
                           (not (role? (last (last %)))))
                      true
                      :else false)
               (partition 2 config))))

;;
;; API
;; ===
;;

(defn current-user []
  (or *current-user* (session-get :current-user)))

(defn current-username []
  (:name (current-user)))

(defn current-user-roles []
  (:roles (current-user)))

(defn any-role-granted?
  "Determine if any of the passed roles are granted. The first argument must
   be the request unless we are running in a context in which
   *current-user* is defined."
  [& roles]
  (let [user-roles (current-user-roles)]
    (intersect-exists? user-roles (set roles))))

(defn access-error
  ([] (access-error "Access Denied!"))
  ([n] (throw+ {:type :access-error :custom-message n})))

(defn authentication-error
  ([] (authentication-error "No Authenticated User!"))
  ([n] (throw+ {:type :authentication-error :custom-message n})))

(defmacro ensure-authenticated [& body]
  `(if *current-user*
     (do ~@body)
     (authentication-error)))

(defmacro ensure-any-role [roles & body]
  `(ensure-authenticated
    (if (apply any-role-granted? ~roles)
      (do ~@body)
      (access-error (str "The user "
                         (current-username)
                         " is not in one of "
                         ~roles)))))

(defmacro ensure-any-role-if [& clauses]
  (if (odd? (count clauses))
    (if (= 1 (count clauses))
      (first clauses)
      (list 'if (first clauses)
            (list 'org.pupcus.authentication/ensure-any-role (second clauses) (last clauses))
            (cons 'org.pupcus.authentication/ensure-any-role-if (drop 2 clauses))))
    (throw (IllegalArgumentException.
            "ensure-any-role-if must have an odd number of forms"))))

(defn logout! [props]
  (let [logout-page (if-let [p (:logout-page props)]
                      (cpath p)
                      (cpath "/"))]
    (redirect
     (do (session-delete-key! :current-user)
         logout-page))))

(defn ^:dynamic with-secure-channel
  "Middleware function to redirect to either a secure or insecure channel."
  [handler config port ssl-port]
  (fn [request]
    (let [ssl-config (filter-channel-config config)
          channel-req (find-matching-config ssl-config request)
          uri (:uri request)]
      (cond (and (= channel-req :ssl) (= (:scheme request) :http))
            (redirect-301 (to-https request ssl-port))
            (and (= channel-req :nossl) (= (:scheme request) :https))
            (redirect-301 (to-http request port))
            :else (handler request)))))

(defn with-security
  "Middleware function for authentication and authorization."
  ([handler auth-fn] (with-security handler [] auth-fn ""))
  ([handler config auth-fn] (with-security handler config auth-fn ""))
  ([handler config auth-fn uri-prefix]
     (fn [request]
       (let [required-roles (required-roles config request)
             user (current-user)
             user-status (if (and (auth-required? required-roles)
                                  (nil? user))
                           (auth-fn request)
                           user)]
         (cond (redirect? user-status)
               (append-to-redirect-loc user-status uri-prefix)
               (allow-access? required-roles (:roles user-status))
               (binding [*current-user* user-status]
                 (try+
                  (handler request)
                  (catch [:type :access-error] _
                    (redirect-to-permission-denied uri-prefix))
                  (catch [:type :authentication-error] _
                    (if *current-user*
                      (redirect-to-authentication-error uri-prefix)
                      (let [user-status (auth-fn request)]
                        (if (redirect? user-status)
                          (append-to-redirect-loc user-status
                                                  uri-prefix)
                          (do (session-put! :current-user
                                            user-status)
                              (set! *current-user*
                                    user-status)
                              ((with-security handler config auth-fn uri-prefix) request))))))))
               :else (redirect-to-permission-denied uri-prefix))))))

