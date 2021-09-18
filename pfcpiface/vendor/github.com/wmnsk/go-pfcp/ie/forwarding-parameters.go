// Copyright 2019-2021 go-pfcp authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package ie

import (
	log "github.com/sirupsen/logrus"
)

// NewForwardingParameters creates a new ForwardingParameters IE.
func NewForwardingParameters(ies ...*IE) *IE {
	return newGroupedIE(ForwardingParameters, 0, ies...)
}

// ForwardingParameters returns the IEs above ForwardingParameters if the type of IE matches.
func (i *IE) ForwardingParameters() ([]*IE, error) {
	switch i.Type {
	case ForwardingParameters:
		log.Println("Case FP")
		return ParseMultiIEs(i.Payload)
	case CreateFAR:
		log.Println("Case Create FAR")
		ies, err := i.CreateFAR()
		if err != nil {
			log.Println("ERROR: Case Create FAR")
			return nil, err
		}
		for _, x := range ies {
			if x.Type == ForwardingParameters {
				return x.ForwardingParameters()
			}
		}
		log.Println("ERROR: ErrIENotFpund")
		return nil, ErrIENotFound
	default:
		log.Println("Case Default")
		return nil, &InvalidTypeError{Type: i.Type}
	}
}
