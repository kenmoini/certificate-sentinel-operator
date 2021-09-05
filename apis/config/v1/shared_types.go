/*
Copyright 2021 Polyglot Systems.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	//"time"
)

// TimeSlices is just a simple TimeSlice slice
type TimeSlices []TimeSlice

// TimeSlice provides the k:v pairing for expiration dates and what daysOut gate triggered it
type TimeSlice struct {
	Time    metav1.Time
	DaysOut int
}
