package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"os/exec"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"

	myerrors "errors"

	myhttp "net/http"

	"github.com/briandowns/spinner"
	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	kubernetes "k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/restmapper"
	clientcmd "k8s.io/client-go/tools/clientcmd"
)

var (
	client                  *github.Client
	NotMergableError        = myerrors.New("Not mergable")
	BranchNotFoundError     = myerrors.New("Branch not found")
	NonDeletableBranchError = myerrors.New("Branch cannot be deleted")
	PullReqNotFoundError    = myerrors.New("Pull request not found")
)

const CREATE = "Create"
const APPLY = "Apply"
const DELETE = "Delete"
const LATEST = "latest"

const CILIUM_VESION = "cilium.io/v2"
const CILIUM_KIND = "CiliumNetworkPolicy"
const CILIUM_KIND_NODE_LABEL = "CiliumClusterwideNetworkPolicy"

const FORMAT_STRING = "%s:%s@tcp(%s:%s)/%s"

const UPDATE = "Update"

const SUCCESS = "success"

const SYSTEM_API_VERSION = "security.kubearmor.com/v1"
const KUBEARMORHOST_POLICY = "KubeArmorHostPolicy"
const KUBEARMOR_POLICY = "KubeArmorPolicy"
const GCP = "GCP"

var current_dir, git_dir, user_home, keyword, tags, ad_dir string
var s = spinner.New(spinner.CharSets[9], 100*time.Millisecond)
var policy_count int = 0
var label_count int = 0
var autoapply bool

var git_username, git_token, git_repo_url, git_branch_name, git_repo_path, git_policy_name, git_base_branch string

const repo_path = "/tmp/accuknox-client-repo"

// Git Functions

func Init_Git(username string, token string, repo_url string, branch_name string) {

	s := strings.Split(repo_url, "/")
	var repoName string

	for i := 0; i < len(s); i++ {
		if strings.Contains(s[i], ".git") {
			repoName = strings.Split(s[i], ".")[0]
		}
	}

	r := GitClone(username, token, repo_url, repo_path)

	createBranch(r, username, token, branch_name)
	fmt.Printf("%v branch is created\n", branch_name)

	pushToGithub(r, username, token)
	fmt.Printf("Pushed to the github repo %v\n", repo_url)

	createPRToGit(token, branch_name, username, repoName)

	removeLocalRepo()
}

func GitClone(username string, token string, repo_url string, repo_path string) *git.Repository {

	if _, err := os.Stat(repo_path); os.IsNotExist(err) {
		os.Mkdir(repo_path, 0755)
	}

	auth := &http.BasicAuth{
		Username: username,
		Password: token,
	}

	r, _ := git.PlainClone(repo_path, false, &git.CloneOptions{
		URL:           repo_url,
		ReferenceName: plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", git_base_branch)),
		Auth:          auth,
	})

	return r
}

func createBranch(r *git.Repository, username string, token string, branch_name string) {

	w, _ := r.Worktree()

	err := w.Checkout(&git.CheckoutOptions{
		Create: true,
		Force:  false,
		Branch: plumbing.ReferenceName(git_base_branch),
	})

	checkError(err, "create branch: checkout "+git_base_branch)

	branchName := plumbing.ReferenceName("refs/heads/" + branch_name)

	err = w.Checkout(&git.CheckoutOptions{
		Create: true,
		Force:  false,
		Branch: branchName,
	})

	checkError(err, "create branch: checkout "+branch_name)

	if _, err := os.Stat(git_repo_path); os.IsNotExist(err) {
		os.Mkdir(git_repo_path, 0755)
	}
	k8s_labels(autoapply)

	CopyDir(git_repo_path, repo_path)
	w.Add(".")

	author := &object.Signature{
		Name:  "KnoxAutoPol",
		Email: "vishnu@accuknox.com",
		When:  time.Now(),
	}

	w.Commit("Commit from KnoxAutoPol CLI", &git.CommitOptions{Author: author})
}

func pushToGithub(r *git.Repository, username, password string) {

	auth := &http.BasicAuth{
		Username: username,
		Password: password,
	}

	err := r.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth:       auth,
		Force:      true,
	})

	checkError(err, "pushtogit error")
}

func newClient(token string) *github.Client {
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)

}

func createPRToGit(token string, branchName string, username string, repoName string) {

	newPR := &github.NewPullRequest{
		Title:               github.String("PR from KnoxAutoPol CLI"),
		Head:                github.String(branchName),
		Base:                github.String(git_base_branch),
		Body:                github.String("This is an automated PR created by KnoxAutoPol CLI"),
		MaintainerCanModify: github.Bool(true),
	}

	pr, _, err := client.PullRequests.Create(context.Background(), username, repoName, newPR)
	if err != nil {
		fmt.Println("There is a Git Error " + err.Error())
		return
	}

	fmt.Printf("PR created: %s\n", pr.GetHTMLURL())
	s := strings.Split(pr.GetHTMLURL(), "/")
	mergePullRequest(username, repoName, s[len(s)-1], token)

}

func stringToInt(number string) int {
	intVal, err := strconv.Atoi(number)
	if err != nil {
		fmt.Printf("[%s] Oops! String to integer conversion failed\n", color.RedString("ERR"))
		log.Warn(err)
	}
	return intVal
}

func mergePullRequest(owner, repo, number, token string) error {
	fmt.Printf("Attempting to merge PR #%s on %s/%s...\n", number, owner, repo)

	commitMsg := "Commit from Accuknox GitOps CLI"
	_, _, mergeErr := client.PullRequests.Merge(
		context.Background(),
		owner,
		repo,
		stringToInt(number),
		commitMsg,
		&github.PullRequestOptions{},
	)

	if mergeErr != nil {
		fmt.Println("Received an error!", mergeErr)
	} else {
		fmt.Printf("Successfully merged PR #%s on %s/%s...\n", number, owner, repo)

	}

	return nil
}

func removeLocalRepo() {

	err := os.RemoveAll(repo_path)
	checkError(err, "removelocalrepo function")
}

func checkError(err error, data string) {
	if err != nil {
		fmt.Printf("[%s] Oops! Error from \n"+data, color.RedString("ERR"))
		log.Warn(err)
	}
}

func CopyDir(src string, dst string) error {
	var err error
	var fds []os.FileInfo
	var srcinfo os.FileInfo

	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}

	if err = os.MkdirAll(dst, srcinfo.Mode()); err != nil {
		return err
	}

	if fds, err = ioutil.ReadDir(src); err != nil {
		return err
	}

	for _, fd := range fds {
		srcfp := path.Join(src, fd.Name())
		dstfp := path.Join(dst, fd.Name())

		if fd.IsDir() {
			if err = CopyDir(srcfp, dstfp); err != nil {
				fmt.Println(err)
			}
		} else {
			if err = file(srcfp, dstfp); err != nil {
				fmt.Println(err)
			}
		}
	}
	return nil
}

func file(src, dst string) error {
	var err error
	var srcfd *os.File
	var dstfd *os.File
	var srcinfo os.FileInfo

	if srcfd, err = os.Open(src); err != nil {
		return err
	}
	defer srcfd.Close()

	if dstfd, err = os.Create(dst); err != nil {
		return err
	}
	defer dstfd.Close()

	if _, err = io.Copy(dstfd, srcfd); err != nil {
		return err
	}
	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}
	return os.Chmod(dst, srcinfo.Mode())
}

// END Git Functions

// function to clone policy-template repo to current working directory
func git_clone() {

	log.Info("Started Cloning policy-template repository")
	fmt.Printf("[%s][%s] Cloning policy-template repository\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.BlueString("INIT"))
	r, err := git.PlainClone(git_dir, false, &git.CloneOptions{
		URL: "https://github.com/kubearmor/policy-templates",
	})

	if err != nil {
		log.Error(err)
	}
	log.Info(r)
	fmt.Printf("[%s][%s] Cloned policy-template repository\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.GreenString("DONE"))

}

// function to pull latest changes into policy-template folder
func git_pull() {

	log.Info("Started Pulling into policy-template repository")
	fmt.Printf("[%s][%s] Fetching updates from policy-template repository\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.BlueString("INIT"))
	r, err := git.PlainOpen(git_dir)
	if err != nil {
		log.Error(err)
	}

	w, err := r.Worktree()
	if err != nil {
		log.Error(err)
	}

	err = w.Pull(&git.PullOptions{RemoteName: "origin"})
	if err != nil {
		log.Debug(err)
	}

	fmt.Printf("[%s][%s] Fetched updates from policy-template repository\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.GreenString("DONE"))

}

// Function to Create connection to kubernetes cluster
func connectToK8s() *kubernetes.Clientset {
	log.Info("Trying to establish connection to k8s")
	home, exists := os.LookupEnv("HOME")
	if !exists {
		home = "/root"
	}

	configPath := filepath.Join(home, ".kube", "config")

	config, err := clientcmd.BuildConfigFromFlags("", configPath)
	if err != nil {
		log.Error("failed to create K8s config")
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Error("Failed to create K8s clientset")
		fmt.Printf("[%s] Failed to connect to Kubernetes cluster. Please try again.\n", color.RedString("ERR"))
	}

	return clientset
}

// Function to create strings from key-value pairs
func createKeyValuePairs(m map[string]string, disp bool, namespace string) string {

	log.Info("Started map to string conversion on labels")

	b := new(bytes.Buffer)
	if disp == true {
		for key, value := range m {
			if strings.Contains(key, keyword) || strings.Contains(value, keyword) {
				fmt.Fprintf(b, "%s: %s\n\t\t\t\t\t", key, value)
			} else if tags == "" && keyword == "" {
				fmt.Fprintf(b, "%s: %s\n\t\t\t\t\t", key, value)
			}
		}

	} else {
		for key, value := range m {
			if strings.Contains(key, keyword) || strings.Contains(value, keyword) {
				fmt.Fprintf(b, "%s: %s\n      ", key, value)
			} else if tags == "" && keyword == "" {
				fmt.Fprintf(b, "%s: %s\n      ", key, value)
			}
		}
	}
	return b.String()
}

// FUnction to search files with .yaml extension under policy-template folder
func policy_search(namespace string, labels string, search string) {

	log.Info("Started searching for files with .yaml extension under policy-template folder")

	err := filepath.Walk(git_dir, func(path string, info os.FileInfo, err error) error {
		log.Info("git directory accessed : " + git_dir)
		if err != nil {
			log.Error(err)
			return err
		}
		if strings.Contains(path, ".yaml") {
			label_count = 0
			policy_read(path, namespace, labels, search)
		}
		return nil
	})
	if err != nil {
		log.Error(err)
		fmt.Printf("[%s] Oops! No files found with .yaml extension. Please try again later.\n", color.RedString("ERR"))
	}
	err = filepath.Walk(ad_dir, func(path string, info os.FileInfo, err error) error {
		log.Info("Started Policy search : " + path + " with labels '" + labels + "' and search '" + search + "'")

		CopyDir(ad_dir, repo_path)
		return nil
	})
	if err != nil {
		log.Error(err)
		fmt.Printf("[%s] Oops! No files found with .yaml extension. Please try again later.\n", color.RedString("ERR"))
	}
}

func policy_read(policy_name string, namespace string, labels string, search string) {

	log.Info("Started Policy search : " + policy_name + " with labels '" + labels + "' and search '" + search + "'")

	content, err := os.ReadFile(policy_name)
	if err != nil {
		log.Error(err)
	}

	if strings.Contains(string(content), search) {

		file, err := os.Open(policy_name)
		if err != nil {
			log.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		var text []string
		text = append(text, "---")
		for scanner.Scan() {
			if strings.Contains(string(scanner.Text()), "name:") {
				policy_val := strings.FieldsFunc(string(scanner.Text()), Split)
				git_policy_name = strings.Replace(policy_val[1]+"-"+shortID(7), "\"", "", -1)

				text = append(text, string(scanner.Text())+"-"+shortID(7))
				for scanner.Scan() {
					if strings.Contains(string(scanner.Text()), "namespace:") {
						break
					}
				}
			}
			if strings.Contains(string(scanner.Text()), "namespace:") {
				text = append(text, "  namespace: "+namespace)
				for scanner.Scan() {
					if strings.Contains(string(scanner.Text()), "spec:") {
						break
					}
				}

			} else if strings.Contains(string(scanner.Text()), "matchLabels:") && label_count == 0 {
				text = append(text, "    matchLabels:\n      "+labels)
				label_count = 1
				for scanner.Scan() {
					if strings.Contains(string(scanner.Text()), "file:") || strings.Contains(string(scanner.Text()), "process:") || strings.Contains(string(scanner.Text()), "network:") || strings.Contains(string(scanner.Text()), "capabilities:") || strings.Contains(string(scanner.Text()), "ingress:") || strings.Contains(string(scanner.Text()), "egress:") {
						break
					}
				}
			}
			text = append(text, scanner.Text())
		}

		file.Close()

		policy_updated, err = os.OpenFile(git_repo_path+git_policy_name+".yaml", os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error(err)
			return
		}

		for _, each_ln := range text {
			_, err = fmt.Fprintln(policy_updated, each_ln)
			if err != nil {
				log.Error(err)
			}
		}

	}

	if strings.Contains(string(content), keyword) && keyword != "" && tags == "" {

		file, err := os.Open(policy_name)
		if err != nil {
			log.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		var text []string
		text = append(text, "---")
		for scanner.Scan() {
			if strings.Contains(string(scanner.Text()), "namespace:") {

				text = append(text, "  namespace: "+namespace)
				for scanner.Scan() {
					if strings.Contains(string(scanner.Text()), "spec:") {
						break
					}
				}

			} else if strings.Contains(string(scanner.Text()), "matchLabels:") && label_count == 0 {
				text = append(text, "    matchLabels:\n      "+labels)
				label_count = 1
				for scanner.Scan() {
					if strings.Contains(string(scanner.Text()), "file:") || strings.Contains(string(scanner.Text()), "process:") || strings.Contains(string(scanner.Text()), "network:") || strings.Contains(string(scanner.Text()), "capabilities:") || strings.Contains(string(scanner.Text()), "ingress") || strings.Contains(string(scanner.Text()), "egress") {
						break
					}
				}
			}
			text = append(text, scanner.Text())
		}

		file.Close()

		policy_updated, err = os.OpenFile(git_repo_path+git_policy_name+".yaml", os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error(err)
			return
		}

		for _, each_ln := range text {
			_, err = fmt.Fprintln(policy_updated, each_ln)
			if err != nil {
				log.Error(err)
			}
		}
	}

}

var chars = "abcdefghijklmnopqrstuvwxyz1234567890-"

func shortID(length int) string {
	ll := len(chars)
	b := make([]byte, length)
	rand.Read(b) // generates len(b) random bytes
	for i := 0; i < length; i++ {
		b[i] = chars[int(b[i])%ll]
	}
	return string(b)
}

func k8s_apply(path string) {

	if autoapply == true {
		log.Info("auto-apply = " + strconv.FormatBool(autoapply))

		log.Info("Trying to establish connection to k8s")
		home, exists := os.LookupEnv("HOME")
		if !exists {
			home = "/root"
		}

		configPath := filepath.Join(home, ".kube", "config")

		config, err := clientcmd.BuildConfigFromFlags("", configPath)
		if err != nil {
			log.Error("failed to create K8s config")
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Error("Failed to create K8s clientset")
			fmt.Printf("[%s] Failed to create Kubernetes Clientset.\n", color.RedString("ERR"))

		}
		log.Info(clientset)

		b, err := ioutil.ReadFile(path)
		if err != nil {
			log.Error(err)
		}

		dd, err := dynamic.NewForConfig(config)
		if err != nil {
			log.Error(err)
		}
		discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
		if err != nil {
			fmt.Printf("[%s] Oops! discovery client creation failed\n", color.RedString("ERR"))
			log.Warn(err.Error())
		}
		log.Info(discoveryClient)

		var namespaceNames string
		namespaceNames = ""
		//Fetch the NamespaceNames using NamespaceID

		Decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(b), 98)
		for {
			var rawObject runtime.RawExtension
			if err = Decoder.Decode(&rawObject); err != nil {
				log.Warn("decoding not possible because " + err.Error())

			}
			//decode yaml into unstructured.Unstructured and get Group version kind
			object, gvk, err := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme).Decode(rawObject.Raw, nil, nil)
			unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
			if err != nil {
				log.Warn("Error in Unstructuredmap because " + err.Error())
			}

			unstructuredObject := &unstructured.Unstructured{Object: unstructuredMap}
			grs, err := restmapper.GetAPIGroupResources(clientset.DiscoveryClient)
			if err != nil {
				log.Warn("Unable to Get API Group resource because " + err.Error())
			}

			//Get Group version resource using Group version kind
			rMapper := restmapper.NewDiscoveryRESTMapper(grs)
			log.Info("Group  Kind :  " + fmt.Sprint(gvk.GroupKind()))
			log.Info("Version :  " + fmt.Sprint(gvk.Version))
			mapping, err := rMapper.RESTMapping(gvk.GroupKind(), gvk.Version)
			if err != nil {
				log.Warn("unexpected error getting mapping for Group version resource " + err.Error())
			}

			// Obtain REST interface for the Group version resource and checking for namespace or cluster wide resource
			var dri dynamic.ResourceInterface

			if gvk.Kind == KUBEARMORHOST_POLICY {
				if namespaceNames != "" {
					dri = dd.Resource(mapping.Resource)

				} else {

					dri = dd.Resource(mapping.Resource)
				}
			} else if gvk.Kind == CILIUM_KIND_NODE_LABEL {
				if namespaceNames != "" {

					dri = dd.Resource(mapping.Resource)
				}
			} else {

				dri = dd.Resource(mapping.Resource).Namespace(unstructuredObject.GetNamespace())
			}

			//To Create or update the policy get the name of the policy which is to be applied and check exist or not

			getObj, err := dri.Get(context.TODO(), unstructuredObject.GetName(), v1.GetOptions{})

			// if policy is not applied or found, create the policy in cluster
			if err != nil && errors.IsNotFound(err) {
				_, err = dri.Create(context.Background(), unstructuredObject, v1.CreateOptions{})
				if err != nil {
					log.Warn("Policy Creation is failed " + err.Error())
				}
				log.Info("Policy Apply Successfully")
			} else {
				//Update the policy in cluster
				unstructuredObject.SetResourceVersion(getObj.GetResourceVersion())
				_, err = dri.Update(context.TODO(), unstructuredObject, v1.UpdateOptions{})
				if err != nil {
					log.Warn("Policy Updation is failed " + err.Error())
				}
				log.Info("Policy Updated Successfully")
			}

			/*
				decoder := yamlutil.NewYAMLOrJSONDecoder(bytes.NewReader(b), 100)
				for {
					s.Prefix = "Applied " + strconv.Itoa(policy_count) + " policies. Please wait.."
					s.Start()
					time.Sleep(4 * time.Second)
					var rawObj runtime.RawExtension
					if err = decoder.Decode(&rawObj); err != nil {
						break
					}

					obj, gvk, err := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme).Decode(rawObj.Raw, nil, nil)
					unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
					if err != nil {
						log.Error(err)
					}

					unstructuredObj := &unstructured.Unstructured{Object: unstructuredMap}

					gr, err := restmapper.GetAPIGroupResources(clientset.Discovery())
					if err != nil {
						log.Error(err)
					}

					mapper := restmapper.NewDiscoveryRESTMapper(gr)
					mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
					if err != nil {
						log.Error(err)
						fmt.Printf("[%s] Error: %v\n", color.RedString("ERR"), err)
					} else {
						policy_count++
					}

					var dri dynamic.ResourceInterface
					if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
						if unstructuredObj.GetNamespace() == "" {
							unstructuredObj.SetNamespace("default")
						}
						dri = dd.Resource(mapping.Resource).Namespace(unstructuredObj.GetNamespace())
					} else {
						dri = dd.Resource(mapping.Resource)
					}
					log.Info(dri)
					applyOptions := apply.NewApplyOptions(dd, discoveryClient)
					if err := applyOptions.Apply(context.TODO(), []byte(b)); err != nil {
						log.Error("Apply error: %v", err)
						fmt.Printf("[%s] Error in Applying Policy\n", color.RedString("ERR"))
					}

				}
			*/
		}
		if err != io.EOF {
			log.Error("End of File ", err)
		}
		s.Stop()
	} else {
		log.Warn("auto-apply = " + strconv.FormatBool(autoapply))
	}

}

func k8s_labels(flag bool) {

	clientset := connectToK8s()
	// access the API to list pods
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), v1.ListOptions{})
	if err != nil {
		log.Error(err)
	}
	var temp []string
	var count int = 0
	for _, pod := range pods.Items {
		if createKeyValuePairs(pod.GetLabels(), true, pod.GetNamespace()) != "" {
			temp = append(temp, createKeyValuePairs(pod.GetLabels(), true, pod.GetNamespace()))
			count++
		}
	}
	if count == 0 {
		fmt.Printf("[%s] No labels found in the cluster. Gracefully exiting program.\n", color.RedString("ERR"))
		os.Exit(1)
	} else {
		fmt.Printf("[%s][%s] Found %d Labels\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.BlueString("Label Count"), count)
	}
	for _, item := range temp {
		val := strings.TrimSuffix(item, "\n\t\t\t\t\t")

		fmt.Printf("[%s][%s]    %s\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.BlueString("Label Details"), val)
		log.Info("Label values: ", item)
	}
	if tags == "" && keyword == "" {
		s.Prefix = "Searching the Kubernetes Cluster for workloads. Please wait.. "
	} else if tags != "" && keyword != "" {
		s.Prefix = "Searching the Kubernetes Cluster for keyword " + keyword + " and tags " + tags + ". Please wait.. "
	}
	for _, pod := range pods.Items {
		labels := createKeyValuePairs(pod.GetLabels(), false, pod.GetNamespace())
		labels = strings.TrimSuffix(labels, "\n      ")
		searchVal := strings.FieldsFunc(labels, Split)
		if labels != "" {
			//	fmt.Printf("[%s][%s] Pod: %s || Labels: %s || Namespace: %s\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.BlueString("Label Details"), pod.GetName(), labels, pod.GetNamespace())
			for i := 0; i < len(searchVal); i++ {
				i++
				policy_search(pod.GetNamespace(), labels, searchVal[i])
			}
		}
	}
	fmt.Printf("[%s][%s] Policy file created at %s\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.BlueString("File Details"), color.GreenString(current_dir+"/policy_updated.yaml"))
	if flag == false {
		log.Info("Received flag value false")

		fmt.Printf("[%s][%s] Halting execution because auto-apply is not enabled\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.CyanString("WRN"))
	} else {
		fmt.Printf("[%s][%s] Started applying policies\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.BlueString("INIT"))
	}
	err = filepath.Walk(git_repo_path, func(path string, info os.FileInfo, err error) error {
		log.Info("git directory accessed : " + git_repo_path)
		if err != nil {
			log.Error(err)
			return err
		}
		if strings.Contains(path, ".yaml") {
			k8s_apply(path)
		}
		return nil
	})
	if err != nil {
		log.Error(err)
		fmt.Printf("[%s] Oops! No files found with .yaml extension. Please try again later.\n", color.RedString("ERR"))
	}

}

func Split(r rune) bool {
	return r == ':' || r == '\n'
}

func banner() {

	figure.NewFigure("Knox AutoPol", "standard", true).Print()
	fmt.Println()
	fmt.Println()
	fmt.Printf("[%s] Uses KubeConfig file to connect to cluster.\n", color.CyanString("WRN"))
	fmt.Printf("[%s] Creates files and folders in current directory.\n", color.CyanString("WRN"))

}

func git_operation() {

	//check if the policy-template directory exist
	// if exist pull down the latest changes
	// else clone the policy-templates repo
	if _, err := os.Stat(git_dir); !os.IsNotExist(err) {

		git_pull()

	} else {

		git_clone()

	}

}
func delete_all() {
	logs_path := current_dir + "/logs.log"
	err := os.RemoveAll(logs_path)
	if err != nil {
		log.Error(err)
		fmt.Printf("[%s] Unable to remove file %s\n", color.RedString("ERR"), logs_path)
	}
	err = os.RemoveAll(git_dir)
	if err != nil {
		log.Error(err)
		fmt.Printf("[%s] Unable to remove folder %s\n", color.RedString("ERR"), git_dir)
	}
}
func auto_discover() {
	fileUrl := "https://raw.githubusercontent.com/accuknox/tools/main/install.sh"
	err := DownloadFile("install.sh", fileUrl)
	if err != nil {
		log.Warn(err)
	}
	fmt.Println("Downloaded: " + fileUrl)
	command_query := "install.sh"
	cmd := exec.Command("/bin/bash", command_query)
	stdout, err := cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(string(stdout))
	log.Info(stdout)
	e := os.Remove(command_query)
	if e != nil {
		log.Fatal(e)
	}
	ad_dir = current_dir + "/ad-policy"
	if _, err := os.Stat(ad_dir); os.IsNotExist(err) {
		os.Mkdir(ad_dir, os.ModeDir|0755)
	}

	os.Chdir(ad_dir)
	log.Info("ad directory :" + ad_dir)

	fileUrl = "https://raw.githubusercontent.com/accuknox/tools/main/get_discovered_yamls.sh"
	err = DownloadFile("get_discovered_yamls.sh", fileUrl)
	if err != nil {
		log.Warn(err)
	}
	fmt.Println("Downloaded: " + fileUrl)
	command_query = "get_discovered_yamls.sh"
	cmd = exec.Command("/bin/bash", command_query)
	stdout, err = cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	e = os.Remove(command_query)
	if e != nil {
		log.Fatal(e)
	}
	fmt.Println(string(stdout))
	log.Info(stdout)
	os.Chdir(current_dir)

}
func DownloadFile(filepath string, url string) error {

	// Get the data
	resp, err := myhttp.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

var version string = "1.0.0"
var policy_updated *os.File

func main() {

	// logging function generating following output
	// log.Info("") --> {"level":"info","msg":"","time":"2022-03-17T14:51:30+05:30"}
	// log.Warn("") --> {"level":"warning","msg":"","time":"2022-03-17T14:51:30+05:30"}
	// log.Error("") -- {"level":"error","msg":"","time":"2022-03-17T14:51:30+05:30"}

	log.SetFormatter(&log.JSONFormatter{})

	log_file, err := os.OpenFile("logs.log", os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(log_file)

	// to get the current working directory
	current_dir, err = os.Getwd()
	if err != nil {
		log.Error(err)
	}
	git_repo_path = current_dir + "/updated_policy/"
	user_home, err = os.UserHomeDir()
	if err != nil {
		log.Error(err)
	}

	// adding policy-template directory to current working directory
	git_dir = current_dir + "/policy-template"

	log.Info("Current Working directory: " + current_dir)
	log.Info("Github clone directory: " + git_dir)
	log.Info("User Home directory: " + user_home)
	tags = ""
	keyword = ""

	myFlags := []cli.Flag{
		&cli.StringFlag{
			Name:        "git_username",
			Aliases:     []string{"git_user"},
			Usage:       "GitHub username",
			EnvVars:     []string{},
			FilePath:    "",
			Required:    false,
			Hidden:      false,
			TakesFile:   false,
			Value:       "",
			DefaultText: "",
			Destination: new(string),
			HasBeenSet:  false,
		},
		&cli.StringFlag{
			Name:        "git_repo_url",
			Aliases:     []string{"git_url"},
			Usage:       "GitHub URL to push the updates",
			EnvVars:     []string{},
			FilePath:    "",
			Required:    false,
			Hidden:      false,
			TakesFile:   false,
			Value:       "",
			DefaultText: "",
			Destination: new(string),
			HasBeenSet:  false,
		},
		&cli.StringFlag{
			Name:        "git_token",
			Aliases:     []string{"token"},
			Usage:       "GitHub token for authentication",
			EnvVars:     []string{},
			FilePath:    "",
			Required:    false,
			Hidden:      false,
			TakesFile:   false,
			Value:       "",
			DefaultText: "",
			Destination: new(string),
			HasBeenSet:  false,
		},
		&cli.StringFlag{
			Name:        "git_branch_name",
			Aliases:     []string{"branch"},
			Usage:       "GitHub branch name for pushing updates",
			EnvVars:     []string{},
			FilePath:    "",
			Required:    false,
			Hidden:      false,
			TakesFile:   false,
			Value:       "",
			DefaultText: "",
			Destination: new(string),
			HasBeenSet:  false,
		},
		&cli.StringFlag{
			Name:        "git_base_branch",
			Aliases:     []string{"basebranch"},
			Usage:       "GitHub base branch name for PR creation",
			EnvVars:     []string{},
			FilePath:    "",
			Required:    false,
			Hidden:      false,
			TakesFile:   false,
			Value:       "",
			DefaultText: "",
			Destination: new(string),
			HasBeenSet:  false,
		},
		&cli.BoolFlag{
			Name:        "auto-apply",
			Aliases:     []string{"auto"},
			Usage:       "If true, modifed YAML will be applied to the cluster",
			EnvVars:     []string{},
			FilePath:    "",
			Required:    false,
			Hidden:      false,
			Value:       false,
			DefaultText: "",
			Destination: new(bool),
			HasBeenSet:  false,
		},
	}
	app := &cli.App{
		Name:      "knox-autopol",
		Usage:     "A simple CLI tool to automatically generate and apply policies or push to GitHub",
		Version:   version,
		UsageText: "knox-autopol [Flags]\nEg. knox-autopol --git_base_branch=deploy-branch --auto-apply=false --git_branch_name=temp-branch --git_token=gh_token123 --git_repo_url= https://github.com/testuser/demo.git --git_username=testuser",
		Flags:     myFlags,
		Action: func(c *cli.Context) error {
			git_username = c.String("git_username")
			git_token = c.String("git_token")
			git_repo_url = c.String("git_repo_url")
			git_branch_name = c.String("git_branch_name")
			autoapply = c.Bool("auto-apply")
			client = newClient(git_token)
			git_base_branch = c.String("git_base_branch")
			banner()
			git_operation()
			auto_discover()
			Init_Git(git_username, git_token, git_repo_url, git_branch_name)
			return nil
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))

	err = app.Run(os.Args)
	if err != nil {
		log.Error(err)
	}

}
