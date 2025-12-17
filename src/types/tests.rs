// Add tests for ReturnStack for VecStack
#[cfg(test)]
#[cfg(feature = "alloc")]
mod tests {
    use crate::types::stack::BoxStack;
    use crate::types::stack::ReturnStack;
    use crate::types::stack::StaticStack;
    use crate::types::stack::VecStack;

    macro_rules! underflow_test {
        ($n:ident, $stack_type:ty) => {
            #[test]
            fn $n() {
                let mut s = <$stack_type>::new(2).unwrap();
                assert_eq!(s.pop(), None);
                assert_eq!(s.depth(), 0);

                s.push(10);
                s.pop();
                assert_eq!(s.pop(), None);
            }
        };
    }

    macro_rules! return_stack_implementation {
        ($n:ident, $stack_type:ty) => {
            #[test]
            fn $n() {
                let mut s = <$stack_type>::new(3).unwrap();
                s.push(1);
                s.push(2);
                s.push(3);
                assert_eq!(s.depth(), 3);
                assert_eq!(s.max_depth(), 3);

                s.push(4);
                assert_eq!(s.depth(), 3);
                assert_eq!(s.pop(), Some(4));
                assert_eq!(s.pop(), Some(3));
                assert_eq!(s.pop(), Some(2));
                assert_eq!(s.pop(), None);
            }
        };
    }

    macro_rules! none_return_stack {
        ($n:ident, $stack_type:ty) => {
            #[test]
            fn $n() {
                let mut s = <$stack_type>::new(0);
                assert!(s.is_none());
            }
        };
    }

    #[test]
    fn none_return_static() {
        let mut s = StaticStack::<2>::new(3);
        assert!(s.is_none());
    }
    underflow_test!(vector_stack_under, VecStack);
    underflow_test!(box_stack_under, BoxStack);
    underflow_test!(static_stack_under, StaticStack<2>);

    return_stack_implementation!(vector_implementation, VecStack);
    return_stack_implementation!(box_implmentation, BoxStack);
    return_stack_implementation!(static_implementation, StaticStack<3>);

    none_return_stack!(vector_return_none, VecStack);
    none_return_stack!(box_return_none, BoxStack);
}
