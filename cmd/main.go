package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
	"github.com/go-git/go-git/v5"
	"github.com/pytimer/k8sutil/apply"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"k8s.io/apimachinery/pkg/api/meta"
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

var current_dir, git_dir, user_home, keyword string
var s = spinner.New(spinner.CharSets[9], 100*time.Millisecond)
var policy_count int = 0

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
func createKeyValuePairs(m map[string]string) string {

	log.Info("Started map to string conversion on labels")
	b := new(bytes.Buffer)
	for key, value := range m {
		if strings.Contains(key, keyword) || strings.Contains(value, keyword) {
			fmt.Fprintf(b, "%s: %s\n", key, value)
		}
	}
	return b.String()
}

// FUnction to search files with .yaml extension under policy-template folder
func policy_search(namespace string, labels string) {

	log.Info("Started searching for files with .yaml extension under policy-template folder")

	err := filepath.Walk(git_dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Error(err)
			return err
		}
		if strings.Contains(path, ".yaml") {
			policy_read(path, namespace, labels)
		}
		return nil
	})
	if err != nil {
		log.Error(err)
		fmt.Printf("[%s] Oops! No files found with .yaml extension. Please try again later.\n", color.RedString("ERR"))
	}
}

func policy_read(policy_name string, namespace string, labels string) {

	log.Info("Started Policy search with keyword '" + keyword + "'")

	content, err := os.ReadFile(policy_name)
	if err != nil {
		log.Error(err)
	}
	if strings.Contains(string(content), keyword) {

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

			} else if strings.Contains(string(scanner.Text()), "matchLabels:") {
				text = append(text, "    matchLabels:\n      "+labels)
				for scanner.Scan() {
					if strings.Contains(string(scanner.Text()), "file:") || strings.Contains(string(scanner.Text()), "process:") || strings.Contains(string(scanner.Text()), "network:") || strings.Contains(string(scanner.Text()), "capabilities:") || strings.Contains(string(scanner.Text()), "ingress") || strings.Contains(string(scanner.Text()), "egress") {
						break
					}
				}
			}
			text = append(text, scanner.Text())
		}

		file.Close()
		f, err := os.OpenFile("policy_updated.yaml", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Error(err)
			return
		}
		for _, each_ln := range text {
			_, err = fmt.Fprintln(f, each_ln)
			if err != nil {
				log.Error(err)
			}
		}

	}

}

func k8s_apply(path string) {

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
		panic(err.Error())
	}

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
			log.Fatal(err)
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
		policy_count++
	}
	if err != io.EOF {
		log.Error("End of File ", err)
	}
	s.Stop()
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
		s.Prefix = "Searching the Kubernetes Cluster for keyword " + keyword + ". Please wait.. "
		s.Start()
		time.Sleep(4 * time.Second)
		if createKeyValuePairs(pod.GetLabels()) != "" {
			temp = append(temp, createKeyValuePairs(pod.GetLabels()))
			count++
		}
	}
	s.Stop()

	if count == 0 {
		fmt.Printf("[%s] No labels found in the cluster. Gracefully exiting program.\n", color.RedString("ERR"))
		os.Exit(0)
	} else {
		fmt.Printf("[%s][%s] Found %d Labels\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.BlueString("Label Details"), count)
	}
	for i, item := range temp {
		log.Info("Label values", i+1, item)
	}

	if flag == false {
		log.Info("Received flag value false")
		fmt.Printf("[%s][%s] Halting execution because auto-apply is not enabled\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.CyanString("WRN"))
		os.Exit(0)
	}
	s.Prefix = "Searching the policy-template repository for policies with keyword " + keyword + ". Please wait.."
	s.Start()
	time.Sleep(4 * time.Second)
	s.Stop()
	for _, pod := range pods.Items {
		labels := createKeyValuePairs(pod.GetLabels())
		labels = strings.TrimSuffix(labels, "\n")
		if labels != "" {
			fmt.Printf("[%s][%s] Pod: %s || Labels: %s || Namespace: %s\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.BlueString("Label Details"), pod.GetName(), labels, pod.GetNamespace())
			policy_search(pod.GetNamespace(), labels)
		}
	}
	fmt.Printf("[%s][%s] Policy file found at %s\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.BlueString("File Details"), color.GreenString(current_dir+"/policy_updated.yaml"))
	fmt.Printf("[%s][%s] Started applying policies\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.BlueString("INIT"))
	k8s_apply(current_dir + "/policy_updated.yaml")

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
	file1 := current_dir + "/logs.log"
	file2 := current_dir + "/policy_updated.yaml"
	err := os.RemoveAll(file1)
	if err != nil {
		log.Error(err)
		fmt.Printf("[%s] Unable to remove file %s\n", color.RedString("ERR"), file1)
	}
	err = os.RemoveAll(file2)
	if err != nil {
		log.Error(err)
		fmt.Printf("[%s] Unable to remove file %s\n", color.RedString("ERR"), file2)
	}
	err = os.RemoveAll(git_dir)
	if err != nil {
		log.Error(err)
		fmt.Printf("[%s] Unable to remove folder %s\n", color.RedString("ERR"), git_dir)
	}
}

var version string = "1.0.0"

func main() {

	// logging function generating following output
	// log.Info("") --> {"level":"info","msg":"","time":"2022-03-17T14:51:30+05:30"}
	// log.Warn("") --> {"level":"warning","msg":"","time":"2022-03-17T14:51:30+05:30"}
	// log.Error("") -- {"level":"error","msg":"","time":"2022-03-17T14:51:30+05:30"}

	log.SetFormatter(&log.JSONFormatter{})

	log_file, err := os.OpenFile("logs.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal(err)
	}
	log.SetOutput(log_file)

	// to get the current working directory
	current_dir, err = os.Getwd()
	if err != nil {
		log.Error(err)
	}

	user_home, err = os.UserHomeDir()
	if err != nil {
		log.Error(err)
	}

	// adding policy-template directory to current working directory
	git_dir = current_dir + "/policy-template"

	log.Info("Current Working directory: " + current_dir)
	log.Info("Github clone directory: " + git_dir)
	log.Info("Current Working directory: " + user_home)

	myFlags := []cli.Flag{
		&cli.StringFlag{
			Name:        "keyword",
			Aliases:     []string{"k"},
			Usage:       "Keyword to search. Example 'wordpress'",
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
			Name:        "persist",
			Aliases:     []string{"p"},
			Usage:       "If true, all logs and modified YAML will be persisted on disk",
			EnvVars:     []string{},
			FilePath:    "",
			Required:    false,
			Hidden:      false,
			Value:       true,
			DefaultText: "",
			Destination: new(bool),
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
		Usage:     "A simple CLI tool to automatically generate and apply policies",
		Version:   version,
		UsageText: "knox-autopol [Flags]\nEg. knox-autopol --keyword=wordpress --auto-apply=true --persist=true",
		Flags:     myFlags,
		Action: func(c *cli.Context) error {
			if c.String("keyword") == "" && c.Bool("persist") == true && c.Bool("auto-apply") == false {

				banner()
				fmt.Printf("[%s] No Keyword found. Please use knox_autopol --help for help menu\n", color.RedString("ERR"))

			}
			if c.String("keyword") != "" {
				keyword = c.String("keyword")
				banner()
				fmt.Printf("[%s] Using Knox AutoPol Engine %s\n", color.BlueString("INF"), color.GreenString(version))
				git_operation()
				k8s_labels(c.Bool("auto-apply"))
				if c.Bool("persist") == false {
					delete_all()
				}
				fmt.Printf("[%s][%s] Successfully applied %d policies\n", color.BlueString(time.Now().Format("01-02-2006 15:04:05")), color.GreenString("DONE"), policy_count)
			}
			return nil
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))

	err = app.Run(os.Args)
	if err != nil {
		log.Error(err)
	}
}
