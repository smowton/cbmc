package com.diffblue.java_testcase;

import org.mockito.stubbing.Answer;
import org.mockito.invocation.InvocationOnMock;
import java.util.ArrayList;

public class IterAnswer<T> implements Answer<T> {

    private int idx = 0;
    private ArrayList<T> answers;

    public IterAnswer(ArrayList<T> _answers) {
	answers = _answers;
    }
    
    public T answer(InvocationOnMock invocation) {
        if(idx == answers.size())
        {
          System.out.println("WARNING: more answers than in trace " +
                             (idx + 1) +
                             " instead of just " + idx +
                             " will restart with first");
          idx = 0;
        }
        T result = answers.get(idx);
        idx++;
	return result;
    }    

}

