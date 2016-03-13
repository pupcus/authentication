;; Copyright (c) pupcus.org. All rights reserved.
;; Copyright (c) Brenton Ashworth. All rights reserved.
;; The use and distribution terms for this software are covered by the
;; Eclipse Public License 1.0 (http://opensource.org/licenses/eclipse-1.0.php)
;; which can be found in the file COPYING at the root of this distribution.
;; By using this software in any fashion, you are agreeing to be bound by
;; the terms of this license.
;; You must not remove this notice, or any other, from this software.

(ns org.pupcus.authentication.test
  (:use [clojure.test :only [deftest testing is]]
        [slingshot.slingshot :only [try+]]
        [org.pupcus.authentication]
        [org.pupcus.stateful-sessions :only [*session*]]
        [ring.util.response :only [redirect]]))

(def fixture-security-config
     [#"/admin.*"                          [:admin :ssl]
      #"/idea/edit.*"                      :editor
      #"/download.*"                       [#{:admin :editor} :ssl]
      #"/secure.*"                         :ssl
      #"/login.*"                          [:any :ssl]
      #"/permission-denied.*"              :any
      #".*.css|.*.png"                     [:any :any-channel]
      #(.endsWith ^String (:uri %) ".js")  :any
      #".*"                                [#{:admin :user} :nossl]])



;;
;; Working with context paths
;;

(deftest set-app-context!-test
  (binding [app-context (atom "")]
    (let [result (set-app-context! "/a")])
    (is (= @app-context "/a"))))

(deftest cpath-test
  (binding [app-context (atom "/a")]
    (is (= (cpath "/b")
           "/a/b"))
    (is (= (cpath "b")
           "b")))
  (binding [app-context (atom "")]
    (is (= (cpath "/b")
           "/b"))
    (is (= (cpath "b")
           "b"))))

(deftest remove-cpath-test
  (binding [app-context (atom "/a")]
    (is (= (remove-cpath "/a/b")
           "/b"))
    (is (= (remove-cpath "/b")
           "/b"))
    (is (= (remove-cpath "b")
           "b")))
  (binding [app-context (atom "")]
    (is (= (remove-cpath "/b")
           "/b"))
    (is (= (remove-cpath "b")
           "b"))))

;;
;; Redirects
;;

(deftest redirect?-test
  (is (true? (redirect? (redirect-301 "/a"))))
  (is (true? (redirect? {:status 302
                        :headers {"Location" "/a"}})))
  (is (false? (redirect? {:status 200}))))

(deftest append-to-redirect-loc-test
  (testing "append to redirect location"
     (binding [app-context (atom "")]
       (testing "when append is blank"
          (is (= (append-to-redirect-loc (redirect-301 "/p") "")
                 (redirect-301 "/p"))))
       (testing "when append is nil"
          (is (= (append-to-redirect-loc (redirect-301 "/p") nil)
                 (redirect-301 "/p"))))
       (testing "when there is something to append"
          (is (= (append-to-redirect-loc (redirect-301 "/p") "/t")
                 (redirect-301 "/t/p"))))
       (testing "does nothing when loc is a complete URL with http scheme"
          (is (= (append-to-redirect-loc (redirect-301 "http://x/p") "/t")
                 (redirect-301 "http://x/p"))))
       (testing "does nothing when loc is a complete URL with https scheme"
          (is (= (append-to-redirect-loc (redirect-301 "https://x/p") "/t")
                 (redirect-301 "https://x/p")))))
     (binding [app-context (atom "/context")]
       (testing "when append is blank and there is a context"
          (is (= (append-to-redirect-loc (redirect-301 "/p") "")
                 (redirect-301 "/p"))))
       (testing "when there is something to append and there is a context"
          (is (= (append-to-redirect-loc (redirect-301 "/p") "/t")
                 (redirect-301 "/t/p")))))))


;;
;; Helpers
;; =======
;;

(defn create-request
  ([scheme server uri] (create-request scheme server uri ""))
  ([scheme server uri query]
     (let [port (if (= scheme :http) 8080 8443)]
       (create-request scheme server uri port query)))
  ([scheme server uri port query]
     {:uri uri
      :scheme (keyword scheme)
      :query-string query
      :server-name server
      :server-port port}))

;;
;; Tests
;; =====
;;

(deftest test-role-set
  (is (= (role-set #{:user})
         #{:user}))
  (is (= (role-set :user)
         #{:user}))
  (is (nil? (role-set :ssl)))
  (is (nil? (role-set :nossl)))
  (is (nil? (role-set :any-channel))))

(deftest test-find-matching-config
  (testing "find mathing config"
     (let [config [[#"/a.*" :a] [#"/b.*" :b]]]
       (is (find-matching-config config 
                                 {:uri "/a/page"})
           :a)
       (is (find-matching-config config
                                 {:uri "/b/page"})
           :b))))

(deftest test-required-roles
  (testing "get required roles"
     (binding [app-context (atom "")]
       (testing "for an admin page with no context path"
          (is (= (required-roles fixture-security-config
                                 {:uri "/admin/page"})
                 #{:admin})))
       (testing "for an editor page with no context path"
          (is (= (required-roles fixture-security-config
                                 {:uri "/idea/edit"})
                 #{:editor})))
       (testing "for any page with no context path" 
          (is (= (required-roles fixture-security-config
                                 {:uri "/some/random/page"})
                 #{:admin :user})))
       (testing "using a function instead of a regular expression" 
          (is (= (required-roles fixture-security-config
                                 {:uri "/script.js"})
                 #{:any})))
       (testing "for a page that has an :ssl requirement" 
          (is (= (required-roles fixture-security-config
                                 {:uri "/login"})
                 #{:any})))
       (testing "for a page that has ONLY an :ssl requirement but matches another re" 
          (is (= (required-roles fixture-security-config
                                 {:uri "/secure/page"})
                 #{:admin :user}))))
       (binding [app-context (atom "/test-context")]
         (testing "for an admin page with context path"
           (is (= (required-roles fixture-security-config
                                  {:uri "/test-context/admin/page"})
                  #{:admin})))
         (testing "for an editor page with context path"
          (is (= (required-roles fixture-security-config
                                 {:uri "/test-context/idea/edit"})
                 #{:editor})))
         (testing "for any page with context path"
          (is (= (required-roles fixture-security-config
                                 {:uri "/test-context/some/random/page"})
                 #{:admin :user}))))))

(deftest test-allow-access?
  (binding [app-context (atom "")]
    (testing "allow access"
      (testing "when req and actual are :admin"
         (is (true? (allow-access? #{:admin} #{:admin}))))
      (testing "when :admin req but user is in :user"
         (is (false? (allow-access? #{:admin} #{:user}))))
      (testing "when user is black but :any is req"
         (is (true? (allow-access? #{:user :any} #{}))))
      (testing "when user is black but :user is req"
         (is (false? (allow-access? #{:user} #{}))))
      (testing "when user has one of two req roles"
         (is (true? (allow-access? #{:user :admin} #{:admin}))))
      (testing "when user is in role but not the correct one out of two"
         (is (false? (allow-access? #{:editor :admin} #{:user})))))))

(deftest test-auth-required?
  (testing "auth required"
     (testing "when role is :admin"
        (is (= (auth-required? #{:admin}))
            true))
     (testing "when role is :user"
        (is (= (auth-required? #{:user}))
            true))
     (testing "user there is more than one role"
        (is (= (auth-required? #{:admin :user}))
            true))
     (testing "when role is any"
        (is (= (auth-required? #{:any}))
            false))
     (testing "when role set is empty"
        (is (= (auth-required? #{}))
            true))
     (testing "when role set is nil"
        (is (= (auth-required? nil))
            true))))

(deftest test-filter-channel-config
  (testing "filter channel config"
     (let [config [#"/a.*" :role
                   #"/b.*" :ssl]]
       (is (= (last (first (filter-channel-config config)))
              :ssl)))))

(deftest test-any-role-granted?
  (testing "are any of these roles granted"
     (binding [*current-user* {:name "testuser" :roles #{:user}}]
       (testing "passing the request and role is missing"
          (is (false? (any-role-granted? :admin))))
       (testing "passing the request and one matching role"
          (is (true? (any-role-granted? :user)))))
     (binding [*current-user* {:name "testuser"
                                       :roles #{:user :admin}}]
       (testing "passing the request and one of two roles match"
          (is (true? (any-role-granted? :admin))))
       (testing "passing the request and another of the two roles match"
          (is (true? (any-role-granted? :user)))))
     (binding [*current-user* {:name "testuser" :roles #{:admin}}]
       (testing "using *current-user* binding with a matching role"
          (is (true? (any-role-granted? :admin))))
       (testing "using *current-user* binding and no matching role"
          (is (false? (any-role-granted? :user)))))))

(defmacro auth-error->false [& body]
  `(try+
     (do ~@body)
     (catch [:type :authentication-error] {} false)))

(defmacro access-error->false [& body]
  `(try+
     (do ~@body)
     (catch [:type :access-error] {} false)))

(defn test-handler-fn
  ([x] (test-handler-fn x "success"))
  ([x result]
     (swap! x (fn [a b] b) result)
     @x))

(defn auth-failure [test-fn]
  (let [a (atom nil)
        result (auth-error->false
                (test-fn (partial test-handler-fn a)))]
    (is (false? result))
    (is (nil? @a))))

(defn access-failure [test-fn]
  (let [a (atom nil)
        result (access-error->false
                (test-fn (partial test-handler-fn a)))]
    (is (false? result))
    (is (nil? @a))))

(defn auth-success [test-fn]
  (let [a (atom nil)]
    (auth-error->false
     (is (= (test-fn (partial test-handler-fn a))
            "success")))))

(defn access-success [test-fn]
  (let [a (atom nil)]
    (access-error->false
     (is (= (test-fn (partial test-handler-fn a))
            "success")))))

(deftest test-ensure-authenticated
  (binding [*current-user* nil]
    (is (auth-failure #(ensure-authenticated (%)))))
  (binding [*current-user* {:roles #{:user}}]
    (is (auth-success #(ensure-authenticated (%))))))

(deftest test-ensure-any-role
  (binding [*current-user* {:roles #{:user}}]
    (is (access-failure #(ensure-any-role #{:admin} (%))))
    (is (access-success #(ensure-any-role #{:admin :user} (%))))
    (is (access-success #(ensure-any-role #{:user} (%)))))
  (binding [*current-user* nil]
    (is (auth-failure #(ensure-any-role #{:admin} (%))))))

(deftest test-ensure-any-role-if
  (let [x :a]
    (testing "ensure any role if"
       (binding [*current-user* {:roles #{:user}}]
         (testing "when user is not in role"
            (is (access-failure #(ensure-any-role-if (= x :a) #{:admin} (%)))))
         (testing "when user is in role"
            (is (access-success #(ensure-any-role-if (= x :a) #{:user} (%)))))
         (testing "when pred is false"
            (is (access-success #(ensure-any-role-if (= x :b) #{:admin} (%)))))
         (testing "with multiple preds"
            (testing "and user is in roles for second pred"
               (is (access-success #(ensure-any-role-if (= x :b) #{:admin}
                                                        (= x :a) #{:user}
                                                        (%)))))
            (testing "and no true preds"
               (is (access-failure #(ensure-any-role-if (= x :a) #{:admin}
                                                        (= x :b) #{:user}
                                                        (%)))))
            (testing "and user is in roles for the first pred"
               (is (access-success #(ensure-any-role-if (= x :a) #{:user}
                                                        (= x :c) #{:admin}
                                                        (%)))))))
       (testing "user is nil"
          (binding [*current-user* nil]
            (testing "and authorization passes because of no matching pred"
               (is (auth-success #(ensure-any-role-if (= x :b) #{:admin}
                                                      (%)))))
            (testing "and auth fails"
               (is (auth-failure #(ensure-any-role-if (= x :a) #{:admin}
                                                      (%)))))
            (testing "with multiple preds"
               (testing "where the second pred is true and auth fails"
                  (is (auth-failure #(ensure-any-role-if (= x :b) #{:admin}
                                                         (= x :a) #{:user}
                                                         (%)))))
               (testing "where auth is successful because no preds match"
                  (is (auth-success #(ensure-any-role-if (= x :b) #{:admin}
                                                         (= x :c) #{:user}
                                                         (%)))))))))))

(deftest test-with-secure-channel
  (binding [app-context (atom "")]
    (testing "check channel security"
       (binding [with-secure-channel (partial with-secure-channel
                                              :uri
                                              fixture-security-config
                                              8080
                                              8443)]
         (testing "when scheme is http and should be https"
            (is (= ((with-secure-channel)
                    (create-request :http "host" "/admin/page"))
                   (redirect-301 "https://host:8443/admin/page"))))
         (testing "when scheme is https and should be https"
            (is (= ((with-secure-channel)
                    (create-request :https "host" "/admin/page"))
                   "/admin/page")))
         (testing "when scheme is http and should be http"
            (is (= ((with-secure-channel)
                    (create-request :http "host" "/standard-page"))
                   "/standard-page")))
         (testing "when scheme is https and should be http"
            (is (= ((with-secure-channel)
                    (create-request :https "host" "/standard-page"))
                   (redirect-301 "http://host:8080/standard-page"))))
         (testing "when ssl configured in a vector with a set"
            (is (= ((with-secure-channel)
                    (create-request :http "host" "/download/page"))
                   (redirect-301 "https://host:8443/download/page"))))
         (testing "when ssl is configured by itself"
            (is (= ((with-secure-channel)
                    (create-request :http "host" "/secure/page"))
                   (redirect-301 "https://host:8443/secure/page"))))
         (testing "when http -> https with request parameters"
            (is (= ((with-secure-channel)
                    (create-request :http "host" "/admin/p" "id=1&n=h"))
                   (redirect-301 "https://host:8443/admin/p?id=1&n=h"))))
         (testing "when https -> http with request parameters"
            (is (= ((with-secure-channel)
                    (create-request :https "host" "/test.js" "load=x"))
                   (redirect-301 "http://host:8080/test.js?load=x"))))
         (testing "when no ssl config falls through to catch all"
            (is (= ((with-secure-channel)
                    (create-request :http "host" "/test.js"))
                   "/test.js")))
         (testing "when using ssl and can use any channel"
            (is (= ((with-secure-channel)
                    (create-request :https "host" "/test.css"))
                   "/test.css")))
         (testing "when NOT using ssl and can use any channel"
            (is (= ((with-secure-channel)
                    (create-request :http "host" "/test.css"))
                   "/test.css")))))))

(deftest test-with-security
  (testing "with security"
     (testing "url config"
        (binding [*session* (atom {})
                  app-context (atom "")]
          (testing "and some other kind of auth, redirect to PD when not in role"
             (is (= ((with-security :uri fixture-security-config
                       (fn [r] {:roles #{:user}}))
                     {:uri "/admin/page"})
                    (redirect "/permission-denied"))))
          (testing "and some other kind of auth, allow access when in role"
             (is (= ((with-security :uri fixture-security-config
                       (fn [r] {:roles #{:user}}))
                     {:uri "/some/page"})
                    "/some/page")))))
     (testing "and NO url config"
        (binding [*session* (atom {})
                  app-context (atom "")]
          (testing "redirect to authentication error page when in auth-err loop"
             (is (= ((with-security
                       (fn [r] (if (= (:uri r) "/x")
                                 (authentication-error)
                                 "success"))
                       []
                       (fn [r] {:name "t" :roles #{:user}}))
                     {:uri "/x"})
                    (redirect "/authentication-error"))))
          (testing "access page when authentication is successfull"
             (is (= ((with-security
                       (fn [r] (ensure-authenticated
                                "success"))
                       []
                       (fn [r] {:name "t" :roles #{:user}}))
                     {:uri "/x"})
                    "success")))
          (testing "permission denied using ensure-any-role"
             (is (= ((with-security
                       (fn [r] (ensure-any-role [:admin]
                                                "success"))
                       []
                       (fn [r] {:name "t" :roles #{:user}}))
                     {:uri "/x"})
                    (redirect "/permission-denied"))))
          (testing "access allowed using ensure-any-role"
             (is (= ((with-security
                       (fn [r] (ensure-any-role [:user]
                                                "success"))
                       []
                       (fn [r] {:name "t" :roles #{:user}}))
                     {:uri "/x"})
                    "success")))
          (testing "access-allowed using ensure-any-role when multiple roles"
             (is (= ((with-security
                       (fn [r] (ensure-any-role [:admin :user]
                                                "success"))
                       []
                       (fn [r] {:name "t" :roles #{:user}}))
                     {:uri "/x"})
                    "success")))))))

